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

// This file handles IO using the POSIX(/BSD) socket API.

package main

import (
	"time"

	"github.com/gavv/monotime"
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/rctx"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/ringbuf"
)

func (r *Router) posixInput(s *rctx.Sock, stop, stopped chan struct{}) {
	defer liblog.PanicLog()
	defer close(stopped)
	dst := s.Conn.LocalAddr()
	log.Debug("posixInput starting", "addr", dst)
	pkts := make(ringbuf.EntryList, 256)
	// Pre-calculate metrics
	inputLoops := metrics.InputLoops.With(s.Labels)
	inputProcessTime := metrics.InputProcessTime.With(s.Labels)
	pktsRecv := metrics.PktsRecv.With(s.Labels)
	bytesRecv := metrics.BytesRecv.With(s.Labels)
	pktRecvSizes := metrics.PktsRecvSize.With(s.Labels)
	free := func(rp *rpkt.RtrPkt) {
		r.freePkts.Write(ringbuf.EntryList{rp}, true)
	}

Top:
	for {
		select {
		case <-stop:
			log.Debug("posixInput stopping", "addr", dst)
			return
		default:
		}
		n := r.freePkts.Read(pkts, true)
		for i := 0; i < n; i++ {
			inputLoops.Inc()
			rp := pkts[i].(*rpkt.RtrPkt)
			// Get current router context for this packet.
			rp.Ctx = rctx.Get()
			rp.DirFrom = s.Dir
			rp.Free = free
			start := monotime.Now()
			length, src, err := s.Conn.Read(rp.Raw)
			if err != nil {
				log.Error("Error reading from socket", "socket", dst, "err", err)
				rp.Reset()
				for j := i; j < n; j++ {
					rp := pkts[j].(*rpkt.RtrPkt)
					free(rp)
				}
				continue Top
			}
			t := monotime.Since(start).Seconds()
			inputProcessTime.Add(t)
			rp.TimeIn = monotime.Now()
			rp.Raw = rp.Raw[:length] // Set the length of the slice
			rp.Ingress.Dst = dst
			rp.Ingress.Src = src
			rp.Ingress.IfIDs = s.Ifids
			rp.Ingress.LocIdx = s.LocIdx
			pktsRecv.Inc()
			bytesRecv.Add(float64(length))
			pktRecvSizes.Observe(float64(length))
			s.Ring.Write(ringbuf.EntryList{pkts[i]}, true)
		}
	}
}

func (r *Router) posixOutput(s *rctx.Sock, _, stopped chan struct{}) {
	defer liblog.PanicLog()
	defer close(stopped)
	src := s.Conn.LocalAddr()
	log.Info("posixOutput starting", "addr", src)
	epkts := make(ringbuf.EntryList, 256)
	// Pre-calculate metrics
	outputProcessTime := metrics.OutputProcessTime.With(s.Labels)
	bytesSent := metrics.BytesSent.With(s.Labels)
	pktsSent := metrics.PktsSent.With(s.Labels)
	var count int
	var err error
	var start time.Duration
	var t float64
	for {
		n := s.Ring.Read(epkts, true)
		if n < 0 {
			log.Debug("posixOutput stopping", "addr", src)
			return
		}
		for i := 0; i < n; i++ {
			erp := epkts[i].(*rpkt.EgressRtrPkt)
			rp := erp.Rp
			start = monotime.Now()
			if count, err = s.Conn.WriteTo(rp.Raw, erp.Dst); err != nil {
				rp.Error("Error sending packet", "err", err, "dst", erp.Dst)
				goto End
			}
			if count != len(rp.Raw) {
				rp.Error("Unable to write full packet", "len", len(rp.Raw), "written", count)
			}
			t = monotime.Since(start).Seconds()
			outputProcessTime.Add(t)
			bytesSent.Add(float64(count))
			pktsSent.Inc()
		End:
			// Release inner RtrPkt entry
			rp.Release()
		}
	}
}
