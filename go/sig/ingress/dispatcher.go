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
	WorkerCleanupInterval = 60 * time.Second
	// FreeFramesCap is the number of preallocated Framebuf objects.
	FreeFramesCap = 1024
)

var (
	ExternalIngress *snet.Conn
	InternalIngress io.ReadWriteCloser
	FreeFrames      *ringbuf.Ring
)

func init() {
	FreeFrames = ringbuf.New(FreeFramesCap, func() interface{} {
		return NewFrameBuf()
	}, "free", prometheus.Labels{"ringId": "freeFrames"})
}

// Dispatcher reads new encapsulated packets, classifies the packet by
// source ISD-AS -> source host Addr -> Sess Id and hands it off to the
// appropriate Worker, starting a new one if none currently exists.
type Dispatcher struct {
	laddr   *snet.Addr
	workers map[string]*Worker
}

func NewDispatcher(laddr *snet.Addr) *Dispatcher {
	return &Dispatcher{
		laddr:   laddr,
		workers: make(map[string]*Worker),
	}
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
	go d.Read()
	return nil
}

func (d *Dispatcher) Read() {
	frames := make(ringbuf.EntryList, 64)
	lastCleanup := time.Now()
	for {
		n, _ := FreeFrames.Read(frames, true)
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
		if time.Since(lastCleanup) >= WorkerCleanupInterval {
			d.cleanup()
			lastCleanup = time.Now()
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
	var toCleanup []*Worker
	for key, worker := range d.workers {
		if worker.markedForCleanup {
			delete(d.workers, key)
			toCleanup = append(toCleanup, worker)
		} else {
			worker.markedForCleanup = true
		}
	}
	// Perform the stopping in separate go-routine, since worker.Stop can block,
	if len(toCleanup) > 0 {
		go func() {
			for _, worker := range toCleanup {
				worker.Stop()
			}
		}()
	}
}
