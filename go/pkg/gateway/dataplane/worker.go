// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

package dataplane

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	// sigHdrSize is the size of SIG header in bytes.
	sigHdrSize = 16
	// reassemblyListCap is the maximum capacity of a reassembly list.
	reassemblyListCap = 100
	// rlistCleanUpInterval is the interval between clean up of outdated reassembly lists.
	rlistCleanUpInterval = 1 * time.Second
)

type ingressSender interface {
	send([]byte) error
}

// worker handles decapsulation of SIG frames.
type worker struct {
	log.Logger
	Remote           *snet.UDPAddr
	SessID           uint8
	Ring             *ringbuf.Ring
	Metrics          IngressMetrics
	rlists           map[int]*reassemblyList
	markedForCleanup bool
	tunIO            io.WriteCloser
}

func newWorker(remote *snet.UDPAddr, sessID uint8,
	tunIO io.WriteCloser, metrics IngressMetrics) *worker {

	worker := &worker{
		Logger:  log.New("ingress", remote.String(), "sessId", sessID),
		Remote:  remote,
		SessID:  sessID,
		Ring:    ringbuf.New(64, nil, fmt.Sprintf("ingress_%s_%d", remote.IA, sessID)),
		rlists:  make(map[int]*reassemblyList),
		tunIO:   tunIO,
		Metrics: metrics,
	}

	return worker
}

func (w *worker) Stop() {
	w.Ring.Close()
}

func (w *worker) Run() {
	w.Info("IngressWorker starting", "remote", w.Remote.String(), "session_id", w.SessID)
	frames := make(ringbuf.EntryList, 64)
	lastCleanup := time.Now()
	for {
		// This might block indefinitely, thus cleanup will be deferred. However,
		// this is not an issue, since if there is nothing to read we also don't need
		// to do any cleanup.
		n, _ := w.Ring.Read(frames, true)
		if n < 0 {
			break
		}
		for i := 0; i < n; i++ {
			frame := frames[i].(*frameBuf)
			w.processFrame(frame)
			frames[i] = nil
		}
		if time.Since(lastCleanup) >= rlistCleanUpInterval {
			w.cleanup()
			lastCleanup = time.Now()
		}
	}
	w.Info("IngressWorker stopping")
}

// processFrame processes a SIG frame by first writing all completely contained
// packets to the wire and then adding the frame to the corresponding reassembly
// list if needed.
func (w *worker) processFrame(frame *frameBuf) {
	index := int(binary.BigEndian.Uint16(frame.raw[2:4]))
	epoch := int(binary.BigEndian.Uint32(frame.raw[4:8]) & 0xfffff)
	seqNr := binary.BigEndian.Uint64(frame.raw[8:16])
	frame.seqNr = seqNr
	frame.index = index
	frame.snd = w
	// If index == 0 then we can be sure that there is no fragment at the beginning
	// of the frame.
	frame.fragNProcessed = index == 0
	// If index == 0xffff then we can be sure that there are no complete packets in this
	// frame.
	frame.completePktsProcessed = index == 0xffff
	// Add to frame buf reassembly list.
	rlist := w.getRlist(epoch)
	rlist.Insert(frame)
}

func (w *worker) getRlist(epoch int) *reassemblyList {
	rlist, ok := w.rlists[epoch]
	if !ok {
		rlist = newReassemblyList(epoch, reassemblyListCap, w, w.Metrics.FramesDiscarded)
		w.rlists[epoch] = rlist
	}
	rlist.markedForDeletion = false
	return rlist
}

func (w *worker) cleanup() {
	for epoch := range w.rlists {
		rlist := w.rlists[epoch]
		if rlist.markedForDeletion {
			// Reassembly list has been marked for deletion in a previous cleanup run.
			// Remove the reassembly list from the map and then release all frames
			// back to the bufpool.
			delete(w.rlists, epoch)
			go func() {
				defer log.HandlePanic()
				rlist.removeAll()
			}()
		} else {
			// Mark the reassembly list for deletion. If it is not accessed between now
			// and the next cleanup interval, it will be removed.
			rlist.markedForDeletion = true
		}
	}
}

func (w *worker) send(packet []byte) error {
	bytesWritten, err := w.tunIO.Write(packet)
	if err != nil {
		increaseCounterMetric(w.Metrics.SendLocalError, 1)
		return serrors.New("Unable to write to internal ingress", "err", err, "length", len(packet))
	}
	// Update the metrics. Note that we are not doing any filtering yet and so
	// the metrics for packets coming from the remote AS and packets sent to the
	// local network are going to be the same, except for different labels.
	increaseCounterMetric(w.Metrics.IPPktBytesRecv, float64(bytesWritten))
	increaseCounterMetric(w.Metrics.IPPktsRecv, 1)
	increaseCounterMetric(w.Metrics.IPPktBytesLocalSent, float64(bytesWritten))
	increaseCounterMetric(w.Metrics.IPPktsLocalSent, 1)

	return nil
}
