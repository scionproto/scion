// Copyright 2016 ETH Zurich
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

package main

import (
	"net"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/log"
)

func (r *Router) getPktBuf() *rpkt.RPkt {
	// https://golang.org/doc/effective_go.html#leaky_buffer
	var rp *rpkt.RPkt
	select {
	case rp = <-r.freePkts:
		// Got one
		metrics.PktBufReuse.Inc()
		return rp
	default:
		// None available, allocate a new one
		metrics.PktBufNew.Inc()
		rp = new(rpkt.RPkt)
		rp.Raw = make([]byte, pktBufSize)
		return rp
	}
}

func (r *Router) readPosixInput(in *net.UDPConn, dirFrom rpkt.Dir, labels prometheus.Labels,
	q chan *rpkt.RPkt) {
	defer liblog.PanicLog()
	log.Info("Listening", "addr", in.LocalAddr())
	dst := in.LocalAddr().(*net.UDPAddr)
	for {
		metrics.InputLoops.With(labels).Inc()
		rp := r.getPktBuf()
		rp.DirFrom = dirFrom
		start := time.Now()
		length, src, err := in.ReadFromUDP(rp.Raw)
		if err != nil {
			log.Error("Error reading from socket", "socket", dst, "err", err)
			continue
		}
		t := time.Now().Sub(start).Seconds()
		metrics.InputProcessTime.With(labels).Add(t)
		rp.TimeIn = time.Now()
		rp.Raw = rp.Raw[:length] // Set the length of the slice
		rp.Ingress.Src = src
		rp.Ingress.Dst = dst
		metrics.PktsRecv.With(labels).Inc()
		metrics.BytesRecv.With(labels).Add(float64(length))
		q <- rp
	}
}

func (r *Router) writeLocalOutput(out *net.UDPConn, labels prometheus.Labels, rp *rpkt.RPkt) {
	if len(rp.Egress) == 0 {
		rp.Error("Destination not specified")
		return
	}
	for _, epair := range rp.Egress {
		start := time.Now()
		if count, err := out.WriteToUDP(rp.Raw, epair.Dst); err != nil {
			rp.Error("Error sending packet", "err", err)
			return
		} else if count != len(rp.Raw) {
			rp.Error("Unable to write full packet", "len", count)
			return
		}
		t := time.Now().Sub(start).Seconds()
		metrics.OutputProcessTime.With(labels).Add(t)
		metrics.BytesSent.With(labels).Add(float64(len(rp.Raw)))
		metrics.PktsSent.With(labels).Inc()
	}
}

func (r *Router) writeIntfOutput(out *net.UDPConn, labels prometheus.Labels, rp *rpkt.RPkt) {
	if len(rp.Egress) == 0 {
		rp.Error("Destination not specified")
		return
	}
	start := time.Now()
	if count, err := out.Write(rp.Raw); err != nil {
		rp.Error("Error sending packet", "err", err)
		return
	} else if count != len(rp.Raw) {
		rp.Error("Unable to write full packet", "len", count)
		return
	}
	t := time.Now().Sub(start).Seconds()
	metrics.OutputProcessTime.With(labels).Add(t)
	metrics.BytesSent.With(labels).Add(float64(len(rp.Raw)))
	metrics.PktsSent.With(labels).Inc()
}
