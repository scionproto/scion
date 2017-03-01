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

// This file handles IO using the libhsr API (via the go/border/hsr package).

package main

import (
	"net"

	"github.com/gavv/monotime"
	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/border/hsr"
	"github.com/netsec-ethz/scion/go/border/metrics"
	"github.com/netsec-ethz/scion/go/border/rpkt"
	"github.com/netsec-ethz/scion/go/lib/log"
)

// readHSRInput reads batches of packets from libhsr, and dispatches them for
// processing.
//
// libhsr has the concept of Ports, which correspond to the interfaces it
// manages. In order to have per-port metrics (and to ensure each port metric
// is only updated once), readHSRInput uses a map of port IDs to keep track of
// which metrics need updating.
// FIXME(kormat): the chan argument is currently unused.
func (r *Router) readHSRInput(_ chan *rpkt.RtrPkt) {
	defer liblog.PanicLog()
	// Allocate slice of empty packets.
	rpkts := make([]*rpkt.RtrPkt, hsr.MaxPkts)
	for i := range rpkts {
		rpkts[i] = r.getPktBuf()
	}
	usedPorts := make([]bool, len(hsrAddrMs))
	h := hsr.NewHSR()
	// Run forever.
	for {
		start := monotime.Now()
		// Read packets from libhsr.
		count, err := h.GetPackets(rpkts, usedPorts)
		if err != nil {
			log.Error("Error getting packets from HSR", "err", err)
			// Zero the port counters for next loop
			for i := range usedPorts {
				usedPorts[i] = false
			}
			continue
		}
		timeIn := monotime.Now()
		// Iterate over received packets
		for i := 0; i < count; i++ {
			rp := rpkts[i]
			rp.TimeIn = timeIn
			// Process packet.
			r.processPacket(rp)
			metrics.PktProcessTime.Add(monotime.Since(rp.TimeIn).Seconds())
			// Reset packet.
			rp.Reset()
		}
		// Update port metrics
		duration := monotime.Since(start).Seconds()
		for id := range usedPorts {
			if usedPorts[id] {
				usedPorts[id] = false
				labels := hsr.AddrMs[id].Labels
				metrics.InputLoops.With(labels).Inc()
				metrics.InputProcessTime.With(labels).Add(duration)
			}
		}
	}
}

// writeHSROutput sends a single output packet via libhsr.
func (r *Router) writeHSROutput(rp *rpkt.RtrPkt, dst *net.UDPAddr, portID int,
	labels prometheus.Labels) {
	start := monotime.Now()
	hsr.SendPacket(dst, portID, rp.Raw)
	duration := monotime.Since(start).Seconds()
	metrics.OutputProcessTime.With(labels).Add(duration)
	metrics.BytesSent.With(labels).Add(float64(len(rp.Raw)))
	metrics.PktsSent.With(labels).Inc()
}
