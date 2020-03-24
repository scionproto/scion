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
	"fmt"
	"io"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/sig_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/sig/internal/metrics"
)

const (
	// tunDevName is the name of the internal ingress tunnel interface.
	tunDevName = "scion-local"
	// workerCleanupInterval is the interval between worker cleanup rounds.
	workerCleanupInterval = 60 * time.Second
)

// Dispatcher reads new encapsulated packets, classifies the packet by
// source ISD-AS -> source host Addr -> Sess Id and hands it off to the
// appropriate Worker, starting a new one if none currently exists.
type Dispatcher struct {
	workers            map[string]*Worker
	extConn            *snet.Conn
	tunIO              io.ReadWriteCloser
	framesRecvCounters map[metrics.CtrPairKey]metrics.CtrPair
}

func NewDispatcher(tio io.ReadWriteCloser, conn *snet.Conn) *Dispatcher {
	return &Dispatcher{
		tunIO:              tio,
		extConn:            conn,
		framesRecvCounters: make(map[metrics.CtrPairKey]metrics.CtrPair),
		workers:            make(map[string]*Worker),
	}
}

func (d *Dispatcher) Run() error {
	return d.read()
}

func (d *Dispatcher) read() error {
	frames := make(ringbuf.EntryList, 64)
	lastCleanup := time.Now()
	for {
		n := NewFrameBufs(frames)
		for i := 0; i < n; i++ {
			frame := frames[i].(*FrameBuf)
			read, src, err := d.extConn.ReadFrom(frame.raw)
			if err != nil {
				log.Error("IngressDispatcher: Unable to read from external ingress", "err", err)
				if reliable.IsDispatcherError(err) {
					return common.NewBasicError("Problems speaking to dispatcher", err)
				}
				frame.Release()
			} else {
				switch v := src.(type) {
				case *snet.UDPAddr:
					frame.frameLen = read
					frame.sessId = sig_mgmt.SessionType((frame.raw[0]))
					d.updateMetrics(v.IA.IAInt(), frame.sessId, read)
					d.dispatch(frame, v)
				default:
					return common.NewBasicError("Not valid snet address", nil)
				}
			}
			// Clear FrameBuf reference
			frames[i] = nil
		}
		if time.Since(lastCleanup) >= workerCleanupInterval {
			d.cleanup()
			lastCleanup = time.Now()
		}
	}
}

// dispatch dispatches a frame to the corresponding worker, spawning one if none
// exist yet. Dispatching is done based on source ISD-AS -> source host Addr -> Sess Id.
func (d *Dispatcher) dispatch(frame *FrameBuf, src *snet.UDPAddr) {
	dispatchStr := fmt.Sprintf("%s/%s/%s", src.IA, src.Host, frame.sessId)
	// Check if we already have a worker running and start one if not.
	worker, ok := d.workers[dispatchStr]
	if !ok {
		worker = NewWorker(src, frame.sessId, d.tunIO)
		d.workers[dispatchStr] = worker
		go func() {
			defer log.HandlePanic()
			worker.Run()
		}()
	}
	worker.markedForCleanup = false
	worker.Ring.Write(ringbuf.EntryList{frame}, true)
}

// cleanup periodically stops and releases idle workers.
func (d *Dispatcher) cleanup() {
	for key := range d.workers {
		worker := d.workers[key]
		if worker.markedForCleanup {
			delete(d.workers, key)
			go func() {
				defer log.HandlePanic()
				worker.Stop()
			}()
		} else {
			worker.markedForCleanup = true
		}
	}
}

func (d *Dispatcher) updateMetrics(remoteIA addr.IAInt, sessId sig_mgmt.SessionType, read int) {
	key := metrics.CtrPairKey{RemoteIA: remoteIA, SessId: sessId}
	counters, ok := d.framesRecvCounters[key]
	if !ok {
		iaStr := remoteIA.IA().String()
		counters = metrics.CtrPair{
			Pkts:  metrics.FramesRecv.WithLabelValues(iaStr, sessId.String()),
			Bytes: metrics.FrameBytesRecv.WithLabelValues(iaStr, sessId.String()),
		}
		d.framesRecvCounters[key] = counters
	}
	counters.Pkts.Inc()
	counters.Bytes.Add(float64(read))

}
