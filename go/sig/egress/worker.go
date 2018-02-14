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

package egress

import (
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	liblog "github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/sig/metrics"
	"github.com/scionproto/scion/go/sig/mgmt"
	"github.com/scionproto/scion/go/sig/sigcmn"
	"github.com/scionproto/scion/go/sig/siginfo"
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
//   Inside the frame, all encapsulated packets are preceeded by a 2B length
//   field, and then padded to an 8B boundary

const (
	PktLenSize = 2
	MinSpace   = 16
	SigHdrLen  = 8
	MaxSeq     = (1 << 24) - 1
)

type worker struct {
	log.Logger
	iaString      string
	sess          *Session
	currSig       *siginfo.Sig
	currPathEntry *sciond.PathReplyEntry
	frameSentCtrs metrics.CtrPair

	epoch uint16
	seq   uint32
	pkts  ringbuf.EntryList
}

func NewWorker(sess *Session, logger log.Logger) *worker {
	return &worker{
		Logger:   logger,
		iaString: sess.IA.String(),
		sess:     sess,
		frameSentCtrs: metrics.CtrPair{
			Pkts:  metrics.FramesSent.WithLabelValues(sess.IA.String(), sess.SessId.String()),
			Bytes: metrics.FrameBytesSent.WithLabelValues(sess.IA.String(), sess.SessId.String()),
		},
		pkts: make(ringbuf.EntryList, 0, egressBufPkts),
	}
}

func (w *worker) Run() {
	defer liblog.LogPanicAndExit()
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
		egressFreePkts.Write(w.pkts, true)
		for i := range w.pkts {
			w.pkts[i] = nil
		}
	}
	w.Info("EgressWorker: stopping")
	close(w.sess.workerStopped)
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
	n, _ := w.sess.ring.Read(w.pkts, block)
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
	if w.currPathEntry == nil {
		// FIXME(kormat): add some metrics to track this.
		return nil
	}
	if w.currSig == nil {
		// FIXME(kormat): add some metrics to track this.
		return nil
	}
	snetAddr := w.currSig.EncapSnetAddr()
	snetAddr.Path = spath.New(w.currPathEntry.Path.FwdPath)
	if err := snetAddr.Path.InitOffsets(); err != nil {
		return common.NewBasicError("Error initializing path offsets", err)
	}
	snetAddr.NextHopHost = w.currPathEntry.HostInfo.Host()
	snetAddr.NextHopPort = w.currPathEntry.HostInfo.Port

	if w.seq == 0 {
		w.epoch = uint16(time.Now().Unix() & 0xFFFF)
	}
	f.writeHdr(w.sess.SessId, w.epoch, w.seq)
	// Update sequence number for next packet
	w.seq += 1
	if w.seq > MaxSeq {
		w.seq = 0
	}
	bytesWritten, err := w.sess.conn.WriteToSCION(f.raw(), snetAddr)
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
			addrLen = uint16(spkt.AddrHdrLen(w.currSig.Host, sigcmn.Host))
		}
		if remote.sessPath != nil {
			w.currPathEntry = remote.sessPath.pathEntry
		}
		if w.currPathEntry != nil {
			mtu = w.currPathEntry.Path.Mtu
			pathLen = uint16(len(w.currPathEntry.Path.FwdPath))
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

func (f *frame) writeHdr(sessId mgmt.SessionType, epoch uint16, seq uint32) {
	f.b[0] = uint8(sessId)
	common.Order.PutUint16(f.b[1:3], epoch)
	common.Order.PutUintN(f.b[3:6], uint64(seq), 3)
	common.Order.PutUint16(f.b[6:8], f.idx)
}
