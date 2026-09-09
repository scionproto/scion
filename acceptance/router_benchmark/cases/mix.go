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

package cases

import "hash"

// MixFlow is one traffic flow of a mixed workload: a full packet template plus
// the ingress device it is injected on and the egress device the router is
// expected to forward it out of (used to verify forwarding).
type MixFlow struct {
	// Name identifies the underlying traffic pattern (e.g. "in", "br_transit").
	Name string
	// DevIn is the label of the interface the packet is injected on.
	DevIn string
	// DevOut is the label of the interface the router forwards the packet to.
	DevOut string
	// Payload is the SCION-layer payload used to recognise the packet on egress.
	Payload []byte
	// Packet is the full Ethernet+IP+UDP+SCION frame to inject.
	Packet []byte
}

// buildMix turns a set of named single-case builders into a slice of MixFlows,
// reusing the exact packets those cases already produce.
func buildMix(packetSize int, mac hash.Hash, builders []struct {
	name string
	fn   func(int, hash.Hash) (string, string, []byte, []byte)
}) []MixFlow {
	flows := make([]MixFlow, 0, len(builders))
	for _, b := range builders {
		devIn, devOut, payload, packet := b.fn(packetSize, mac)
		flows = append(flows, MixFlow{
			Name:    b.name,
			DevIn:   devIn,
			DevOut:  devOut,
			Payload: payload,
			Packet:  packet,
		})
	}
	return flows
}

// Mix builds a realistic IPv4 workload that exercises every router forwarding
// path at once, reusing each case's own packet builder. Ingress spans the
// internal and external-AS2 links; egress spans the internal and both external links.
func Mix(packetSize int, mac hash.Hash) []MixFlow {
	return buildMix(packetSize, mac, []struct {
		name string
		fn   func(int, hash.Hash) (string, string, []byte, []byte)
	}{
		{"in", In},
		{"out", Out},
		{"br_transit", BrTransit},
		{"in_transit", InTransit},
		{"out_transit", OutTransit},
	})
}

// Mix6 is the IPv6 counterpart of [Mix].
func Mix6(packetSize int, mac hash.Hash) []MixFlow {
	return buildMix(packetSize, mac, []struct {
		name string
		fn   func(int, hash.Hash) (string, string, []byte, []byte)
	}{
		{"in6", In6},
		{"out6", Out6},
		{"br_transit6", BrTransit6},
		{"in_transit6", InTransit6},
		{"out_transit6", OutTransit6},
	})
}
