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

// +build hsr

package main

import (
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/border/hsr"
	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/log"
)

func (r *Router) readHSRInput(q chan *rpkt.RPkt) {
	defer liblog.PanicLog()
	pkts := make([]*rpkt.RPkt, hsr.MaxPkts)
	h := hsr.NewHSR()
	for {
		usedPortIdxs := make(map[int]bool)
		pkts = pkts[:cap(pkts)]
		for i, p := range pkts {
			if p == nil {
				pkts[i] = r.getPktBuf()
			}
		}
		start := time.Now()
		portIds, err := h.GetPackets(pkts)
		duration := time.Now().Sub(start).Seconds()

		if err != nil {
			log.Error("Error getting packets from HSR", "err", err)
			continue
		}
		timeIn := time.Now()
		for i := range pkts[:len(portIds)] {
			p := pkts[i]
			p.TimeIn = timeIn
			labels := hsr.AddrMs[portIds[i]].Labels
			metrics.PktsRecv.With(labels).Inc()
			metrics.BytesRecv.With(labels).Add(float64(len(p.Raw)))
			//q <- p
			r.processPacket(p)
			metrics.PktProcessTime.Add(time.Now().Sub(p.TimeIn).Seconds())
			r.recyclePkt(p)
			pkts[i] = nil
		}
		for _, id := range portIds {
			if _, ok := usedPortIdxs[id]; !ok {
				usedPortIdxs[id] = true
				labels := hsr.AddrMs[id].Labels
				metrics.InputLoops.With(labels).Inc()
				metrics.InputProcessTime.With(labels).Add(duration)
			}
		}
	}
}

func (r *Router) writeHSROutput(p *rpkt.RPkt, portID int, labels prometheus.Labels) {
	for _, epair := range p.Egress {
		if epair.Dst == nil {
			p.Crit("No dst address set")
			continue
		}
		start := time.Now()
		hsr.SendPacket(epair.Dst, portID, p.Raw)
		metrics.OutputProcessTime.With(labels).Add(time.Now().Sub(start).Seconds())
		metrics.BytesSent.With(labels).Add(float64(len(p.Raw)))
		metrics.PktsSent.With(labels).Inc()
	}
}
