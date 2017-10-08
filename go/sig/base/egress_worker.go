// Copyright 2017 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package base

import (
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	liblog "github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/ringbuf"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/lib/snet"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/util"
	"github.com/netsec-ethz/scion/go/sig/metrics"
	"github.com/netsec-ethz/scion/go/sig/sigcmn"
)

//   SIG Frame Header, used to encapsulate SIG to SIG traffic. The sequence
//   number is used to determine packet reordering and loss. The index is used
//   to determine where the first packet in the frame starts. The epoch is used
//   to handle sequence number resets, whether from a SIG restarting, or the
//   sequence number wrapping. The epoch values are the lowest 16b of the unix
//   timestamp at the reset point.
//
//      0B       1        2        3        4        5        6        7
//  +--------+--------+--------+--------+--------+--------+--------+--------+
//  |         Sequence number           |     Index       |      Epoch      |
//  +--------+--------+--------+--------+--------+--------+--------+--------+
//
const (
	PktLenSize = 2
	MinSpace   = 16
	SigHdrLen  = 8
)

type EgressWorker struct {
	ae       *ASEntry
	pol      *PathPolicy
	conn     *snet.Conn
	currPath *sciond.PathReplyEntry

	epoch uint16
	seq   uint32
	pkts  ringbuf.EntryList
}

func NewEgressWorker(ae *ASEntry, pol *PathPolicy, conn *snet.Conn) *EgressWorker {
	return &EgressWorker{ae: ae, pol: pol, conn: conn, currPath: pol.CurrPath(),
		pkts: make(ringbuf.EntryList, 0, egressBufPkts)}
}

func (e *EgressWorker) Run() {
	defer liblog.LogPanicAndExit()
	f := newFrame()

TopLoop:
	for {
		// If the frame is empty, block indefinitely for more packets.
		fEmpty := f.offset == sigcmn.SIGHdrSize
		if !e.Read(fEmpty) {
			break TopLoop
		}
		if fEmpty {
			// Cover the case where no packets have arrived in a while, and the
			// current path is stale.
			e.resetFrame(f)
		} else if len(e.pkts) == 0 {
			// Didn't read any new packets, send partial frame.
			if err := e.Write(f); err != nil {
				log.Error("Error sending frame", "err", err)
			}
			continue TopLoop
		}
		// Process buffered packets.
		for i := range e.pkts {
			pkt := e.pkts[i].(common.RawBytes)
			if err := e.processPkt(f, pkt); err != nil {
				log.Error("Error sending frame", "err", err)
			}
		}
		// Return processed pkts to the free pool, and remove references.
		egressFreePkts.Write(e.pkts, true)
		for i := range e.pkts {
			e.pkts[i] = nil
		}
	}
	log.Info("EgressWorker: stopping", "ia", e.ae.IA)
}

func (e *EgressWorker) processPkt(f *frame, pkt common.RawBytes) error {
	f.startPkt(uint16(len(pkt)))
	pktOff := 0
	// Write chunks of the packet to frames, sending off frames as they fill up.
	for {
		pktOff += f.readFrom(pkt[pktOff:])
		if f.isFull() {
			// There's no point in trying to fit another packet into this frame.
			if err := e.Write(f); err != nil {
				// Skip the rest of this packet.
				return err
			}
		}
		if pktOff == len(pkt) {
			// This packet is now finished, time to get a new one.
			return nil
		}
		// Otherwise continue copying packet into next frame.
	}
}

// Return false if the ringbuf is closed.
func (e *EgressWorker) Read(block bool) bool {
	e.pkts = e.pkts[:cap(e.pkts)]
	n, _ := e.pol.ring.Read(e.pkts, block)
	if n < 0 {
		return false
	}
	e.pkts = e.pkts[:n]
	// FIXME(kormat): add worker read metrics here.
	return true
}

func (e *EgressWorker) Write(f *frame) error {
	// TODO(kormat): consider looking for an updated path here, and switching
	// to it if the mtu isn't smaller than the current one.
	defer e.resetFrame(f)
	if e.currPath == nil {
		// FIXME(kormat): add some metrics to track this.
		return nil
	}
	sig := e.pol.CurrSig()
	if sig == nil {
		// FIXME(kormat): add some metrics to track this.
		return nil
	}
	snetAddr := sig.EncapSnetAddr()
	snetAddr.PathEntry = e.currPath

	if e.seq == 0 {
		e.epoch = uint16(time.Now().Unix() & 0xFFFF)
	}
	f.writeHdr(e.epoch, e.seq)
	//log.Debug("EgressWorker.Write", "len", f.offset, "epoch", e.epoch,
	// "seq", e.seq, "index", f.idx, "raw", f.raw())
	// Update metadata
	e.seq += 1
	bytesWritten, err := e.conn.WriteToSCION(f.raw(), snetAddr)
	if err != nil {
		return common.NewCError("Egress write error", "err", err)
	}
	metrics.FramesSent.WithLabelValues(e.ae.IAString).Inc()
	metrics.FrameBytesSent.WithLabelValues(e.ae.IAString).Add(float64(bytesWritten))
	return nil
}

func (e *EgressWorker) resetFrame(f *frame) {
	e.currPath = e.pol.CurrPath()
	// FIXME(kormat): to do this properly, need to calculate the address header size,
	// and account for any ext headers.
	f.reset(e.currPath.Path.Mtu - spkt.CmnHdrLen - 40 - l4.UDPLen)
}

type frame struct {
	b      common.RawBytes
	idx    uint16
	offset int
}

func newFrame() *frame {
	return &frame{b: make(common.RawBytes, common.MaxMTU), offset: sigcmn.SIGHdrSize}
}

func (f *frame) reset(mtu uint16) {
	f.b = f.b[:int(mtu)]
	f.idx = 0
	f.offset = sigcmn.SIGHdrSize
}

func (f *frame) raw() common.RawBytes {
	return f.b[:f.offset]
}

func (f *frame) readFrom(b common.RawBytes) int {
	copied := copy(f.b[f.offset:], b)
	f.offset += copied
	return copied
}

func (f *frame) isFull() bool {
	return (len(f.b) - f.offset) < MinSpace
}

func (f *frame) startPkt(pktLen uint16) {
	// New packets always starts at a 8 byte boundary.
	f.offset += util.CalcPadding(f.offset, 8)
	if f.idx == 0 {
		// This is the first start of a packet in this frame, so set the index
		f.idx = uint16(f.offset / 8)
	}
	common.Order.PutUint16(f.b[f.offset:], pktLen)
	f.offset += PktLenSize
}

func (f *frame) writeHdr(epoch uint16, seq uint32) {
	common.Order.PutUint32(f.b[:4], seq)
	common.Order.PutUint16(f.b[4:6], f.idx)
	common.Order.PutUint16(f.b[6:8], epoch)
}
