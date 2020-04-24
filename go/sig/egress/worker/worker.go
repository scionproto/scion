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

// Package worker implements the logic for reading packets from a session's
// ring buffer, encapsulating them and writing them to the network as frames.
package worker

import (
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/sig_mgmt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/sig/egress/iface"
	"github.com/scionproto/scion/go/sig/egress/siginfo"
	"github.com/scionproto/scion/go/sig/internal/metrics"
	"github.com/scionproto/scion/go/sig/internal/sigcmn"
)

//   SIG Frame Header, used to encapsulate SIG to SIG traffic. The sequence
//   number is used to determine packet reordering and loss. The index is used
//   to determine where the first packet in the frame starts. The epoch is used
//   to handle sequence number resets, whether from a SIG restarting, or the
//   sequence number wrapping. The epoch values are the lowest 16b of the unix
//   timestamp at the reset point.
//
//   0B       1        2        3        4        5        6        7
//   +--------+--------+--------+--------+--------+--------+--------+--------+
//   | Sess Id|      Epoch      |    Sequence number       |     Index       |
//   +--------+--------+--------+--------+--------+--------+--------+--------+
//
//   Inside the frame, all encapsulated packets are preceded by a 2B length
//   field, and then padded to an 8B boundary

const (
	PktLenSize = 2
	MinSpace   = 16
	SigHdrLen  = 8
	MaxSeq     = (1 << 24) - 1
)

type SCIONWriter interface {
	WriteTo(b []byte, address net.Addr) (int, error)
}

type worker struct {
	log.Logger
	iaString      string
	sess          iface.Session
	writer        SCIONWriter
	currSig       *siginfo.Sig
	currPathEntry snet.Path
	frameSentCtrs metrics.CtrPair

	epoch uint16
	seq   uint32
	pkts  ringbuf.EntryList

	// TODO(sustrik): This is used for testing only. The code should be refactored
	// in such a way that it's not needed.
	ignoreAddress bool
}

// NewWorker creates a new worker object.
// ignoreAddress is set to true only in tests. Elsewhere is should be set to false.
func NewWorker(sess iface.Session, writer SCIONWriter, ignoreAddress bool,
	logger log.Logger) *worker {

	return &worker{
		Logger:        logger,
		iaString:      sess.IA().String(),
		sess:          sess,
		writer:        writer,
		ignoreAddress: ignoreAddress,
		frameSentCtrs: metrics.CtrPair{
			Pkts:  metrics.FramesSent.WithLabelValues(sess.IA().String(), sess.ID().String()),
			Bytes: metrics.FrameBytesSent.WithLabelValues(sess.IA().String(), sess.ID().String()),
		},
		pkts: make(ringbuf.EntryList, 0, iface.EgressBufPkts),
	}
}

func (w *worker) Run() {
	defer log.HandlePanic()
	w.Info("EgressWorker: starting")
	f := newFrame()

TopLoop:
	for {
		// If the frame is empty, block indefinitely for more packets.
		fEmpty := f.offset == sigcmn.SIGHdrSize
		if !w.read(fEmpty) {
			break TopLoop
		}
		if fEmpty {
			// Cover the case where no packets have arrived in a while, and the
			// current path is stale.
			w.resetFrame(f)
		} else if len(w.pkts) == 0 {
			// Didn't read any new packets, send partial frame.
			if err := w.write(f); err != nil {
				w.Error("Error sending frame", "err", err)
			}
			continue TopLoop
		}
		// Process buffered packets.
		for i := range w.pkts {
			pkt := w.pkts[i].(common.RawBytes)
			if err := w.processPkt(f, pkt); err != nil {
				w.Error("Error sending frame", "err", err)
			}
		}
		// Return processed pkts to the free pool, and remove references.
		iface.EgressFreePkts.Write(w.pkts, true)
		for i := range w.pkts {
			w.pkts[i] = nil
		}
	}
	w.Info("EgressWorker: stopping")
	w.sess.AnnounceWorkerStopped()
}

func (w *worker) processPkt(f *frame, pkt common.RawBytes) error {
	f.startPkt(uint16(len(pkt)))
	pktOff := 0
	// Write chunks of the packet to frames, sending off frames as they fill up.
	for {
		pktOff += f.readFrom(pkt[pktOff:])
		if f.isFull() {
			// There's no point in trying to fit another packet into this frame.
			if err := w.write(f); err != nil {
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
func (w *worker) read(block bool) bool {
	w.pkts = w.pkts[:cap(w.pkts)]
	n, _ := w.sess.Ring().Read(w.pkts, block)
	if n < 0 {
		return false
	}
	w.pkts = w.pkts[:n]
	// FIXME(kormat): add worker read metrics here.
	return true
}

func (w *worker) write(f *frame) error {
	// TODO(kormat): consider looking for an updated path here, and switching
	// to it if the mtu isn't smaller than the current one.
	defer w.resetFrame(f)
	if w.seq == 0 {
		w.epoch = uint16(time.Now().Unix() & 0xFFFF)
	}

	// Update the sequence number.
	// We want to do this even if the function fails. Otherwise, if writing fails
	// in the middle of sending a packet the peer wouldn't recognize that there's
	// a frame missing and would try to parse an inconsistent sequence of frames.
	seq := w.seq
	w.seq += 1
	if w.seq > MaxSeq {
		w.seq = 0
	}

	var snetAddr *snet.UDPAddr
	if !w.ignoreAddress {
		if w.currPathEntry == nil {
			// FIXME(kormat): add some metrics to track this.
			return nil
		}
		if w.currSig == nil {
			// FIXME(kormat): add some metrics to track this.
			return nil
		}
		snetAddr = w.currSig.EncapSnetAddr()
		snetAddr.Path = w.currPathEntry.Path()
		snetAddr.NextHop = w.currPathEntry.UnderlayNextHop()
	}

	f.writeHdr(w.sess.ID(), w.epoch, seq)
	bytesWritten, err := w.writer.WriteTo(f.raw(), snetAddr)
	if err != nil {
		return common.NewBasicError("Egress write error", err)
	}
	w.frameSentCtrs.Pkts.Inc()
	w.frameSentCtrs.Bytes.Add(float64(bytesWritten))
	return nil
}

func (w *worker) resetFrame(f *frame) {
	var mtu uint16 = common.MinMTU
	var addrLen, pathLen uint16
	remote := w.sess.Remote()
	if remote != nil {
		w.currSig = remote.Sig
		if w.currSig != nil {
			addrLen = uint16(spkt.AddrHdrLen(w.currSig.Host,
				addr.HostFromIP(sigcmn.DataAddr)))
		}
		w.currPathEntry = nil
		if remote.SessPath != nil {
			w.currPathEntry = remote.SessPath.Path()
		}
		if w.currPathEntry != nil {
			mtu = w.currPathEntry.MTU()
			pathLen = uint16(len(w.currPathEntry.Path().Raw))
		}
	}
	// FIXME(kormat): to do this properly, need to account for any ext headers.
	f.reset(mtu - spkt.CmnHdrLen - addrLen - pathLen - l4.UDPLen)
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

func (f *frame) writeHdr(sessId sig_mgmt.SessionType, epoch uint16, seq uint32) {
	f.b[0] = uint8(sessId)
	common.Order.PutUint16(f.b[1:3], epoch)
	common.Order.PutUintN(f.b[3:6], uint64(seq), 3)
	common.Order.PutUint16(f.b[6:8], f.idx)
}
