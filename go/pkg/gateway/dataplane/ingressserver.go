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
	"fmt"
	"io"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

const (
	// tunDevName is the name of the internal ingress tunnel interface.
	tunDevName = "scion-local"
	// workerCleanupInterval is the interval between worker cleanup rounds.
	workerCleanupInterval = 60 * time.Second
)

type ReadConn interface {
	ReadFrom(b []byte) (int, net.Addr, error)
}

// IngressMetrics are used to report traffic and error statistics for ingress traffic.
type IngressMetrics struct {
	// IPPktBytesRecv is the total IP packets bytes received.
	IPPktBytesRecv metrics.Counter
	// IPPktBytesRecv is the total IP packets count received.
	IPPktsRecv metrics.Counter
	// IPPktBytesLocalSent is the total IP packets bytes sent to the local network.
	IPPktBytesLocalSent metrics.Counter
	// IPPktsLocalSent is the total IP packets counbt sent to the local network.
	IPPktsLocalSent metrics.Counter
	// FrameBytesRecv is the total frames bytes received.
	FrameBytesRecv metrics.Counter
	// FramesRecv is the total frames count received.
	FramesRecv metrics.Counter
	// FramesDiscarded is the total number of discarded frames.
	FramesDiscarded metrics.Counter
	// SendLocalError is the error count when sending IP packets to the local network.
	SendLocalError metrics.Counter
	// ReceiveExternalError is the error count when reading frames from the external network.
	ReceiveExternalError metrics.Counter
}

// IngressServer reads new encapsulated packets, classifies the packet by
// source ISD-AS -> source host Addr -> Sess ID and hands it off to the
// appropriate Worker, starting a new one if none currently exists.
type IngressServer struct {
	Conn    ReadConn
	TUN     io.Writer
	Metrics IngressMetrics

	workers map[string]*worker
}

func (d *IngressServer) Run() error {
	d.workers = make(map[string]*worker)
	return d.read()
}

func (d *IngressServer) read() error {
	frames := make(ringbuf.EntryList, 64)
	lastCleanup := time.Now()
	for {
		n := newFrameBufs(frames)
		for i := 0; i < n; i++ {
			frame := frames[i].(*frameBuf)
			read, src, err := d.Conn.ReadFrom(frame.raw)
			if err != nil {
				log.Error("IngressServer: Unable to read from external ingress", "err", err)
				if reliable.IsDispatcherError(err) {
					return serrors.WrapStr("problems speaking to dispatcher", err)
				}
				increaseCounterMetric(d.Metrics.ReceiveExternalError, 1)
				frame.Release()
			} else {
				switch v := src.(type) {
				case *snet.UDPAddr:
					if read < sigHdrSize {
						metrics.CounterInc(metrics.CounterWith(d.Metrics.FramesDiscarded,
							"remote_isd_as", v.IA.String(), "reason", "invalid"))
						return serrors.New("frame too short",
							"expected", sigHdrSize, "actual", read)
					}
					if frame.raw[0] != 0 {
						metrics.CounterInc(metrics.CounterWith(d.Metrics.FramesDiscarded,
							"remote_isd_as", v.IA.String(), "reason", "invalid"))
						return serrors.New("unsupported SIG protocol version",
							"supported", 0, "actual", frame.raw[0])
					}
					frame.frameLen = read
					frame.sessId = uint8((frame.raw[1]))
					metrics.CounterInc(metrics.CounterWith(d.Metrics.FramesRecv,
						"remote_isd_as", v.IA.String()))
					metrics.CounterAdd(metrics.CounterWith(d.Metrics.FrameBytesRecv,
						"remote_isd_as", v.IA.String()), float64(read))
					d.dispatch(frame, v)
				default:
					return serrors.New("not a valid snet address", "address", src)
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
func (d *IngressServer) dispatch(frame *frameBuf, src *snet.UDPAddr) {
	dispatchStr := fmt.Sprintf("%s/%s/%d", src.IA, src.Host, frame.sessId)
	// Check if we already have a worker running and start one if not.
	worker, ok := d.workers[dispatchStr]
	if !ok {
		metrics := createWorkerMetrics(d.Metrics, src.IA.String())
		worker = newWorker(src, frame.sessId, d.TUN, metrics)
		d.workers[dispatchStr] = worker
		go func() {
			defer log.HandlePanic()
			worker.Run()
		}()
	}
	worker.markedForCleanup = false
	worker.Ring.Write(ringbuf.EntryList{frame}, true)
}

func createWorkerMetrics(in IngressMetrics, remoteIALabel string) IngressMetrics {
	labels := []string{"remote_isd_as", remoteIALabel}
	return IngressMetrics{
		IPPktBytesRecv:      metrics.CounterWith(in.IPPktBytesRecv, labels...),
		IPPktsRecv:          metrics.CounterWith(in.IPPktsRecv, labels...),
		IPPktBytesLocalSent: in.IPPktBytesLocalSent,
		IPPktsLocalSent:     in.IPPktsLocalSent,
		FrameBytesRecv:      metrics.CounterWith(in.FrameBytesRecv, labels...),
		FramesRecv:          metrics.CounterWith(in.FramesRecv, labels...),
		FramesDiscarded:     metrics.CounterWith(in.FramesDiscarded, labels...),
		SendLocalError:      in.SendLocalError,
	}
}

// cleanup periodically stops and releases idle workers.
func (d *IngressServer) cleanup() {
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

func increaseCounterMetric(m metrics.Counter, amount float64) {
	if m != nil {
		m.Add(amount)
	}
}
