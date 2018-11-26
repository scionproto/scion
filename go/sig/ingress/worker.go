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

package ingress

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/sig/metrics"
	"github.com/scionproto/scion/go/sig/mgmt"
)

const (
	// reassemblyListCap is the maximum capacity of a reassembly list.
	reassemblyListCap = 100
	// rlistCleanUpInterval is the interval between clean up of outdated reassembly lists.
	rlistCleanUpInterval = 1 * time.Second
)

type sender interface {
	send(common.RawBytes) error
}

// Worker handles decapsulation of SIG frames.
type Worker struct {
	log.Logger
	Remote           *snet.Addr
	SessId           mgmt.SessionType
	Ring             *ringbuf.Ring
	rlists           map[int]*ReassemblyList
	markedForCleanup bool
	sentCtrs         metrics.CtrPair
}

func NewWorker(remote *snet.Addr, sessId mgmt.SessionType) *Worker {
	// FIXME(kormat): these labels don't allow us to identify traffic from a
	// specific remote sig, but adding the remote sig addr would cause a label
	// explosion :/
	ringLabels := prometheus.Labels{
		"ringId": remote.IA.String(), "sessId": sessId.String(),
	}
	worker := &Worker{
		Logger: log.New("ingress", remote.String(), "sessId", sessId),
		Remote: remote,
		SessId: sessId,
		Ring:   ringbuf.New(64, nil, "ingress", ringLabels),
		rlists: make(map[int]*ReassemblyList),
		sentCtrs: metrics.CtrPair{
			Pkts: metrics.PktsSent.WithLabelValues(remote.IA.String(),
				sessId.String()),
			Bytes: metrics.PktBytesSent.WithLabelValues(remote.IA.String(),
				sessId.String()),
		},
	}
	return worker
}

func (w *Worker) Stop() {
	w.Ring.Close()
}

func (w *Worker) Run() {
	w.Info("IngressWorker starting")
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
			frame := frames[i].(*FrameBuf)
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
func (w *Worker) processFrame(frame *FrameBuf) {
	epoch := int(common.Order.Uint16(frame.raw[1:3]))
	seqNr := int(common.Order.UintN(frame.raw[3:6], 3))
	index := int(common.Order.Uint16(frame.raw[6:8]))
	frame.seqNr = seqNr
	frame.index = index
	frame.snd = w
	//w.Debug("Received Frame", "seqNr", seqNr, "index", index, "epoch", epoch,
	//	"len", frame.frameLen)
	// If index == 1 then we can be sure that there is no fragment at the beginning
	// of the frame.
	frame.fragNProcessed = index == 1
	// If index == 0 then we can be sure that there are no complete packets in this
	// frame.
	frame.completePktsProcessed = index == 0
	// Add to frame buf reassembly list.
	rlist := w.getRlist(epoch)
	rlist.Insert(frame)
}

func (w *Worker) getRlist(epoch int) *ReassemblyList {
	rlist, ok := w.rlists[epoch]
	if !ok {
		rlist = NewReassemblyList(epoch, reassemblyListCap, w)
		w.rlists[epoch] = rlist
	}
	rlist.markedForDeletion = false
	return rlist
}

func (w *Worker) cleanup() {
	for epoch := range w.rlists {
		rlist := w.rlists[epoch]
		if rlist.markedForDeletion {
			// Reassembly list has been marked for deletion in a previous cleanup run.
			// Remove the reassembly list from the map and then release all frames
			// back to the bufpool.
			delete(w.rlists, epoch)
			go func() {
				defer log.LogPanicAndExit()
				rlist.removeAll()
			}()
		} else {
			// Mark the reassembly list for deletion. If it is not accessed between now
			// and the next cleanup interval, it will be removed.
			rlist.markedForDeletion = true
		}
	}
}

func (w *Worker) send(packet common.RawBytes) error {
	bytesWritten, err := tunIO.Write(packet)
	if err != nil {
		return common.NewBasicError("Unable to write to internal ingress", err,
			"length", len(packet))
	}
	w.sentCtrs.Pkts.Inc()
	w.sentCtrs.Bytes.Add(float64(bytesWritten))
	return nil
}
