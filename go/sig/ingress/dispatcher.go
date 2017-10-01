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
	"io"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ringbuf"
	"github.com/netsec-ethz/scion/go/lib/snet"
	"github.com/netsec-ethz/scion/go/sig/metrics"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

const (
	// InternalIngressName is the name of the internal ingress tunnel interface.
	InternalIngressName = "scion.local"
	// WorkerCleanupInterval is the interval between worker cleanup rounds.
	WorkerCleanupInterval = 5 * time.Second
	// FreeFramesCap is the number of preallocated Framebuf objects.
	FreeFramesCap = 1024
)

var (
	ExternalIngress *snet.Conn
	InternalIngress io.ReadWriteCloser
)

// Dispatcher reads new encapsulated packets, classifies the packet by
// source ISD-AS -> source host Addr -> Sess Id and hands it off to the
// appropriate Worker, starting a new one if none currently exists.
type Dispatcher struct {
	laddr        *snet.Addr
	workers      map[string]*Worker
	workersMutex sync.Mutex
	freeFrames   *ringbuf.Ring
}

func NewDispatcher(laddr *snet.Addr) *Dispatcher {
	d := &Dispatcher{
		laddr:   laddr,
		workers: make(map[string]*Worker),
		freeFrames: ringbuf.New(FreeFramesCap, nil, "free",
			prometheus.Labels{"ringId": "freeFrames"}),
	}
	// Fill ringbuf
	entries := make(ringbuf.EntryList, FreeFramesCap)
	for i := 0; i < FreeFramesCap; i++ {
		frame := NewFrameBuf()
		frame.ring = d.freeFrames
		entries[i] = frame
	}
	d.freeFrames.Write(entries, true)
	return d
}

func (d *Dispatcher) Run() error {
	var err error
	ExternalIngress, err = snet.ListenSCION("udp4", d.laddr)
	if err != nil {
		return common.NewCError("Unable to initialize ExternalIngress", "err", err)
	}
	InternalIngress, err = xnet.ConnectTun(InternalIngressName)
	if err != nil {
		return common.NewCError("Unable to connect to InternalIngress", "err", err)
	}
	go d.cleanup()
	go d.Read()
	return nil
}

func (d *Dispatcher) Read() {
	frames := make(ringbuf.EntryList, 32)
	for {
		n, _ := d.freeFrames.Read(frames, true)
		for i := 0; i < n; i++ {
			frame := frames[i].(*FrameBuf)
			read, src, err := ExternalIngress.ReadFromSCION(frame.raw)
			if err != nil {
				log.Error("IngressDispatcher: Unable to read from external ingress", "err", err)
				frame.Release()
			} else {
				frame.frameLen = read
				d.dispatch(frame, src)
				metrics.FramesRecv.WithLabelValues(src.IA.String()).Inc()
				metrics.FrameBytesRecv.WithLabelValues(src.IA.String()).Add(float64(read))
			}
			// Clear FrameBuf reference
			frames[i] = nil
		}
	}
}

// dispatch dispatches a frame to the corresponding worker, spawning one if none
// exist yet. Dispatching is done based on source ISD-AS -> source host Addr -> Sess Id.
func (d *Dispatcher) dispatch(frame *FrameBuf, src *snet.Addr) {
	session := int(frame.raw[1])
	// FIXME(shitz): Remove as soon as egress sets session id correctly.
	session = 0
	dispatchStr := fmt.Sprintf("%s/%s/%d", src.IA, src.Host, session)
	// Check if we already have a worker running and start one if not.
	d.workersMutex.Lock()
	defer d.workersMutex.Unlock()
	var worker *Worker
	worker, ok := d.workers[dispatchStr]
	if !ok {
		worker := NewWorker(src, session)
		worker.Start()
		d.workers[dispatchStr] = worker
	}
	worker.markedForCleanup = false
	worker.Ring.Write(ringbuf.EntryList{frame}, true)
}

// cleanup periodically stops and releases idle workers.
func (d *Dispatcher) cleanup() {
	for {
		time.Sleep(WorkerCleanupInterval)
		// Mark workers for cleanup or add to cleanup slice and remove from the map.
		// Iterating over workers has to be done exclusive to prevent race conditions
		// with the main dispatcher loop. For performance reasons the actual stopping
		// is done outside the exclusive part.
		var toCleanup []*Worker
		d.workersMutex.Lock()
		for key, worker := range d.workers {
			if worker.markedForCleanup {
				delete(d.workers, key)
				toCleanup = append(toCleanup, worker)
			} else {
				worker.markedForCleanup = true
			}
		}
		d.workersMutex.Unlock()
		for _, worker := range toCleanup {
			worker.Stop()
		}
	}
}
