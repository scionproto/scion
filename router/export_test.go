// Copyright 2020 Anapaya Systems
// Copyright 2023 ETH Zurich
// Copyright 2025 SCION Association
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

package router

import (
	"net"
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/private/topology"
)

var (
	dispatchedPortStart = 1024
	dispatchedPortEnd   = 1<<16 - 1
)

func GetMetrics() *Metrics {
	return metrics
}

var NewServices = newServices

type Disposition disposition

const PDiscard = Disposition(pDiscard)

func NewPacket(raw []byte, src, dst *net.UDPAddr, ingress, egress uint16) *Packet {
	p := Packet{
		DstAddr:   &net.UDPAddr{IP: make(net.IP, 0, net.IPv6len)},
		SrcAddr:   &net.UDPAddr{IP: make(net.IP, 0, net.IPv6len)},
		RawPacket: make([]byte, len(raw)),
		Ingress:   ingress,
		egress:    egress,
	}

	if src != nil {
		p.SrcAddr = src
	}
	if dst != nil {
		p.DstAddr = dst
	}
	copy(p.RawPacket, raw)
	return &p
}

// mustMakeDP initializes a dataplane structure configured per the test requirements.
func mustMakeDP(
	external []uint16,
	linkTypes map[uint16]topology.LinkType,
	internal BatchConn,
	internalNextHops map[uint16]netip.AddrPort,
	svc map[addr.SVC][]netip.AddrPort,
	local addr.IA,
	neighbors map[uint16]addr.IA,
	key []byte) (dp dataPlane) {

	dp = makeDataPlane(RunConfig{NumProcessors: 1, BatchSize: 64}, false)

	if err := dp.SetIA(local); err != nil {
		panic(err)
	}
	for i, t := range linkTypes {
		if err := dp.AddLinkType(i, t); err != nil {
			panic(err)
		}
	}
	for i, n := range neighbors {
		if err := dp.AddNeighborIA(i, n); err != nil {
			panic(err)
		}
	}
	dp.SetPortRange(uint16(dispatchedPortStart), uint16(dispatchedPortEnd))

	for id, addresses := range svc {
		for _, addr := range addresses {
			if err := dp.AddSvc(id, addr); err != nil {
				panic(err)
			}
		}
	}

	// Make dummy interfaces, as requested by the test. Only the internal interface is ever used to
	// send or receive and then, not always. So tests can set a nil connections and an empty
	// address. We do it by hand as the Add*Interface methods do not tolerate nil connections and
	// empty addresses. It only makes sense in unit tests.
	dp.addForwardingMetrics(0, Internal)
	dp.interfaces[0] = dp.underlay.NewInternalLink(
		internal, dp.RunConfig.BatchSize, dp.forwardingMetrics[0])
	dp.internalIP = netip.MustParseAddr("198.51.100.1")

	for _, i := range external {
		dp.addForwardingMetrics(i, External)
		dp.interfaces[i] = dp.underlay.NewExternalLink(
			nil, 64, nil, netip.AddrPort{}, i, dp.forwardingMetrics[i])
	}
	for i, addr := range internalNextHops {
		dp.addForwardingMetrics(i, Sibling)
		dp.interfaces[i] = dp.underlay.NewSiblingLink(64, nil, addr, dp.forwardingMetrics[i])
	}

	if err := dp.SetKey(key); err != nil {
		panic(err)
	}

	// The rest is normally done by Run(); it is up to the invoking test:
	// add packet pool
	// add procQs slowQs
	// setRunning
	// start processor and slowPath processor
	// start underlay

	return
}

// newDP constructs a dataPlane structure with makeDataPlane and returns it by reference. It
// returns a pointer to the unexported type, which is usable by internal tests.
func newDP(
	external []uint16,
	linkTypes map[uint16]topology.LinkType,
	internal BatchConn,
	internalNextHops map[uint16]netip.AddrPort,
	svc map[addr.SVC][]netip.AddrPort,
	local addr.IA,
	neighbors map[uint16]addr.IA,
	key []byte) *dataPlane {

	dp := mustMakeDP(external, linkTypes, internal, internalNextHops, svc, local, neighbors, key)
	return &dp
}

// dataPlane is a dataplane structure as an exported type for use by non-internal tests.
type DataPlane struct {
	dataPlane
}

// NewDP constructs a DataPlane structure with makeDataPlane and returns it by reference. It
// returns a pointer to the exported type, which is usable by non-internal tests. A couple of
// methods are added to the exported type.
func NewDP(
	external []uint16,
	linkTypes map[uint16]topology.LinkType,
	internal BatchConn,
	internalNextHops map[uint16]netip.AddrPort,
	svc map[addr.SVC][]netip.AddrPort,
	local addr.IA,
	neighbors map[uint16]addr.IA,
	key []byte) *DataPlane {

	return &DataPlane{
		makeDP(external, linkTypes, internal, internalNextHops, svc, local, neighbors, key),
	}
}

// NewDPRaw constructs a minimaly initialized DataPlane and returns it by reference. This is useful
// to non-internal tests that do not want any dataplane configuration beyond the strictly necessary.
// This is equivalent to router.NewDataPlane, but returns an exported type.
func NewDPRaw(runConfig RunConfig, authSCMP bool) *DataPlane {

	edp := &DataPlane{
		makeDataPlane(runConfig, authSCMP),
	}
	return edp
}

func (d *DataPlane) FakeStart() {
	d.setRunning()
}

func (d *DataPlane) ProcessPkt(pkt *Packet) Disposition {

	p := newPacketProcessor(&d.dataPlane)
	disp := p.processPkt(pkt)
	// Erase trafficType; we don't set it in the expected results.
	pkt.trafficType = ttOther
	return Disposition(disp)
}

func ExtractServices(s *services) map[addr.SVC][]netip.AddrPort {
	return s.m
}
