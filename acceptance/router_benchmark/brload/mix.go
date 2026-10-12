// Copyright 2026 SCION Association
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

//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket/afpacket"

	"github.com/scionproto/scion/acceptance/router_benchmark/cases"
	"github.com/scionproto/scion/pkg/log"
)

// setPromisc toggles promiscuous mode on a device. Best effort.
// Why: the router forwards transit and internal traffic with a next-hop MAC the
// host listener does not own, so without promisc the NIC drops those frames
// before afpacket sees them.
func setPromisc(dev string, on bool) {
	state := "off"
	if on {
		state = "on"
	}
	if err := exec.Command("ip", "link", "set", "dev", dev, "promisc", state).Run(); err != nil {
		log.Info("could not set promiscuous mode", "device", dev, "state", state, "err", err)
	}
}

// MixCase builds a multi-flow workload: several forwarding patterns injected
// concurrently across the router's links.
type MixCase func(packetSize int, mac hash.Hash) []cases.MixFlow

// mixCases are the multi-flow cases. Separate from allCases: they do not fit the
// single-template Case signature.
var mixCases = map[string]MixCase{
	"mix":  cases.Mix,
	"mix6": cases.Mix6,
}

// runMix drives a mixed workload: it groups the flows by ingress device, runs
// one AF_XDP sender per ingress link (each cycling that link's templates), and
// verifies that every egress link forwards traffic. It preserves the output
// contract the test harness parses (metricsBegin/metricsEnd, Listener results).
func runMix(mixFn MixCase, handles map[string]*afpacket.TPacket, hfMAC hash.Hash) int {
	flows := mixFn(packetSize, hfMAC)
	if len(flows) == 0 {
		log.Error("mix case produced no flows")
		return 1
	}

	// Zero the outer UDP checksum (IPv4) on every template, matching the
	// single-case path; the AF_XDP sender recomputes it for IPv6.
	for i := range flows {
		if !isIPv6(flows[i].Packet) {
			off := underlayOffsetsOf(flows[i].Packet).udpCsum
			binary.BigEndian.PutUint16(flows[i].Packet[off:off+2], 0)
		}
	}

	// Group templates by ingress device (preserving first-seen order) and collect
	// the distinct egress devices to listen on.
	byDevIn := map[string][][]byte{}
	var devInOrder []string
	egress := map[string]struct{}{}
	for _, f := range flows {
		if _, ok := handles[f.DevIn]; !ok {
			log.Error("mix ingress device not found", "device", f.DevIn, "flow", f.Name)
			return 1
		}
		if _, ok := handles[f.DevOut]; !ok {
			log.Error("mix egress device not found", "device", f.DevOut, "flow", f.Name)
			return 1
		}
		if _, seen := byDevIn[f.DevIn]; !seen {
			devInOrder = append(devInOrder, f.DevIn)
		}
		byDevIn[f.DevIn] = append(byDevIn[f.DevIn], f.Packet)
		egress[f.DevOut] = struct{}{}
	}
	log.Info("Mix workload",
		"flows", len(flows), "ingress_links", len(devInOrder), "egress_links", len(egress))

	// Each egress device expects the payloads of the flows routed to it. Payload
	// bytes are case-specific (they differ in length with the SCION header size),
	// so a listener matches against every payload destined for its link.
	wantByDev := map[string][][]byte{}
	for _, f := range flows {
		wantByDev[f.DevOut] = append(wantByDev[f.DevOut], f.Payload)
	}

	// One listener per egress device, as a sanity gate that each link forwards
	// its traffic. Throughput comes from the router metrics and per-flow
	// correctness from the acceptance tests, so each listener stops after the
	// first match.
	// Why: matching every packet for the whole run would steal host CPU from the
	// senders and skew the benchmark.
	var stop atomic.Bool
	var lwg sync.WaitGroup
	seen := map[string]*atomic.Bool{}
	for dev := range egress {
		setPromisc(dev, true)
		defer setPromisc(dev, false)
		ok := &atomic.Bool{}
		seen[dev] = ok
		lwg.Add(1)
		go func(h *afpacket.TPacket, ok *atomic.Bool, want [][]byte) {
			defer lwg.Done()
			defer log.HandlePanic()
			for !stop.Load() {
				data, _, err := h.ZeroCopyReadPacketData()
				if err != nil {
					continue // block timeout or transient read error; keep polling
				}
				for _, p := range want {
					if bytes.Contains(data, p) {
						ok.Store(true)
						return // one confirmation per link is enough
					}
				}
			}
		}(handles[dev], ok, wantByDev[dev])
	}

	// One sender per ingress device, each on a disjoint CPU range so per-link
	// workers do not share cores.
	var senders []*xdpSender
	cpuBase := cpuOffset
	for _, dev := range devInOrder {
		s, err := newXdpSenderMulti(dev, byDevIn[dev], xdpConfig{
			txQueues:        txQueues,
			firstQueue:      firstTxQueue,
			cpuOffset:       cpuBase,
			numStreams:      numStreams,
			maxPPS:          maxPPS,
			maxMbps:         maxMbps,
			preferZerocopy:  zerocopy,
			preferHugepages: hugepages,
			numFrames:       numFrames,
			frameSize:       frameSize,
			txRing:          txRing,
			batchSize:       txBatchSize,
			maxPackets:      numPackets,
		})
		if err != nil {
			log.Error("creating mix sender failed", "device", dev, "err", err)
			stop.Store(true)
			lwg.Wait()
			for _, x := range senders {
				x.close()
			}
			return 1
		}
		senders = append(senders, s)
		cpuBase += len(s.workers)
	}

	// Transmit on all ingress links concurrently for the test duration.
	metricsBegin := time.Now().Unix()
	for _, s := range senders {
		s.start()
	}
	time.Sleep(testDuration)
	metricsEnd := time.Now().Unix()

	var total uint64
	for _, s := range senders {
		s.close()
		total += s.sent()
	}

	// Let the last forwarded packets drain, then stop the listeners.
	time.Sleep(200 * time.Millisecond)
	stop.Store(true)
	lwg.Wait()

	log.Info("Mix transmit complete", "packets", total)
	fmt.Printf("metricsBegin: %d metricsEnd: %d\n", metricsBegin, metricsEnd)

	// A correct run forwards traffic out of every egress link.
	confirmed := 0
	allSeen := true
	for dev, ok := range seen {
		forwarded := ok.Load()
		log.Info("Mix egress link", "device", dev, "forwarded", forwarded)
		if forwarded {
			confirmed++
		} else {
			allSeen = false
			log.Error("Mix: egress link saw no forwarded traffic", "device", dev)
		}
	}
	fmt.Printf("Listener results: %d\n", confirmed)
	if !allSeen {
		return 1
	}
	return 0
}
