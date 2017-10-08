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

package ingress

import (
	"fmt"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/lib/common"
	liblog "github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/ringbuf"
	"github.com/netsec-ethz/scion/go/lib/snet"
	"github.com/netsec-ethz/scion/go/sig/metrics"
)

const (
	// reassemblyListCap is the maximum capacity of a reassembly list.
	reassemblyListCap = 100
	// rlistCleanUpInterval is the interval between clean up of outdated reassembly lists.
	rlistCleanUpInterval = 1 * time.Second
)

// Worker handles decapsulation of SIG frames.
type Worker struct {
	Remote           *snet.Addr
	Session          int
	Ring             *ringbuf.Ring
	reassemblyLists  map[int]*ReassemblyList
	running          bool
	markedForCleanup bool
}

func NewWorker(remote *snet.Addr, session int) *Worker {
	ringLabels := prometheus.Labels{"ringId": fmt.Sprintf("%s:%d", remote.String(), session)}
	worker := &Worker{
		Remote:          remote,
		Session:         session,
		Ring:            ringbuf.New(64, nil, "ingress", ringLabels),
		reassemblyLists: make(map[int]*ReassemblyList),
	}
	return worker
}

func (w *Worker) Start() {
	if !w.running {
		go w.run()
		w.running = true
	}
}

func (w *Worker) Stop() {
	if w.running {
		log.Info("IngressWorker stopping", "remote", w.Remote.String(), "session", w.Session)
		w.Ring.Close()
		w.running = false
	}
}

func (w *Worker) run() {
	defer liblog.LogPanicAndExit()
	frames := make(ringbuf.EntryList, 64)
	lastCleanup := time.Now()
	for {
		// This might block indefinitely, thus cleanup will be deferred. However,
		// this is not an issue, since if there is nothing to read we also don't need
		// to do any cleanup.
		n, _ := w.Ring.Read(frames, true)
		if n < 0 {
			return
		}
		for i := 0; i < n; i++ {
			frame := frames[i].(*FrameBuf)
			w.processFrame(frame)
			frames[i] = nil
		}
		if time.Since(lastCleanup) >= rlistCleanUpInterval {
			w.cleanup()
			lastCleanup = time.Now()
		}
	}
}

// processFrame processes a SIG frame by first writing all completely contained
// packets to the wire and then adding the frame to the corresponding reassembly
// list if needed.
func (w *Worker) processFrame(frame *FrameBuf) {
	seqNr := int(common.Order.Uint32(frame.raw[:4]))
	index := int(common.Order.Uint16(frame.raw[4:6]))
	epoch := int(common.Order.Uint16(frame.raw[6:8]))
	frame.seqNr = seqNr
	frame.index = index
	//log.Debug("Received Frame", "seqNr", seqNr, "index", index, "epoch", epoch,
	//	"len", frame.frameLen)
	// If index == 1 then we can be sure that there is no fragment at the beginning
	// of the frame.
	frame.fragNProcessed = index == 1
	// If index == 0 then we can be sure that there are no complete packets in this
	// frame.
	frame.completePktsProcessed = index == 0
	// Add to frame buf reassembly list.
	rlist := w.getReassemblyList(epoch)
	rlist.Insert(frame)
}

func (w *Worker) getReassemblyList(epoch int) *ReassemblyList {
	rlist, ok := w.reassemblyLists[epoch]
	if !ok {
		rlist = NewReassemblyList(epoch, reassemblyListCap)
		w.reassemblyLists[epoch] = rlist
	}
	rlist.markedForDeletion = false
	return rlist
}

func (w *Worker) cleanup() {
	for epoch, rlist := range w.reassemblyLists {
		if rlist.markedForDeletion {
			// Reassembly list has been marked for deletion in a previous cleanup run.
			// Remove the reassembly list from the map and then release all frames
			// back to the bufpool.
			delete(w.reassemblyLists, epoch)
			go rlist.removeAll()
		} else {
			// Mark the reassembly list for deletion. If it is not accessed between now
			// and the next cleanup interval, it will be removed.
			rlist.markedForDeletion = true
		}
	}
}

func send(packet common.RawBytes) error {
	bytesWritten, err := tunIO.Write(packet)
	if err != nil {
		return common.NewCError("Unable to write to internal ingress", "err", err,
			"length", len(packet))
	}
	metrics.PktsSent.WithLabelValues(tunDevName).Inc()
	metrics.PktBytesSent.WithLabelValues(tunDevName).Add(float64(bytesWritten))
	return nil
}
