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
	"github.com/scionproto/scion/router/bfd"
	"github.com/scionproto/scion/router/control"
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

// Implements the link interface minimally
type MockLink struct {
	ifID uint16
}

func (l *MockLink) IsUp() bool                   { return true }
func (l *MockLink) IfID() uint16                 { return l.ifID }
func (l *MockLink) Scope() LinkScope             { return Internal }
func (l *MockLink) BFDSession() *bfd.Session     { return nil }
func (l *MockLink) CheckPktSrc(pkt *Packet) bool { return true }
func (l *MockLink) Send(p *Packet) bool          { return true }
func (l *MockLink) SendBlocking(p *Packet)       {}

func newMockLink(ingress uint16) Link { return &MockLink{ifID: ingress} }

// NewPacket makes a mock packet. It has one shortcoming which makes it unsuited for some tests:
// The packet buffer is strictly no bigger than the supplied bytes; which means that it cannot
// be used to respond via SCMP. Also, it refers to a mock link that has the scope Internal, yet
// will confirm being the carrier of any kind of packet.
func NewPacket(raw []byte, src, dst *net.UDPAddr, ingress, egress uint16) *Packet {
	p := Packet{
		RemoteAddr: &net.UDPAddr{IP: make(net.IP, 0, net.IPv6len)},
		RawPacket:  make([]byte, len(raw)),
		egress:     egress,
		Link:       newMockLink(ingress),
	}
	if src != nil {
		p.RemoteAddr = src
	}
	if dst != nil {
		p.RemoteAddr = dst
	}
	copy(p.RawPacket, raw)
	return &p
}

// mustMakeDP initializes a dataplane structure configured per the test requirements.
// external interfaces are given arbitrary addresses in the range 203.0.113/24 block and
// are not meant to actually carry traffic. The underlying connection is the same as
// the internal one, just to satisfy constraints.
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
	// send or receive and then, not always. The external interfaces are given non-zero
	// addresses in order to satisfy constraints.
	if err := dp.AddInternalInterface(internal, netip.MustParseAddr("198.51.100.1")); err != nil {
		panic(err)
	}
	yes := true
	dummySrc := netip.AddrFrom4([4]byte{203, 0, 113, 0})
	for _, i := range external {
		dummyDst := netip.AddrFrom4([4]byte{203, 0, 113, byte(i)})
		if err := dp.AddExternalInterface(
			i,
			internal, // Just so it isn't nil... do not use!
			control.LinkEnd{Addr: netip.AddrPortFrom(dummySrc, 3333)},
			control.LinkEnd{Addr: netip.AddrPortFrom(dummyDst, 3333)},
			control.BFD{Disable: &yes},
		); err != nil {
			panic(err)
		}
	}
	for i, addr := range internalNextHops {
		if err := dp.AddNextHop(
			i,
			netip.MustParseAddrPort("198.51.100.1:3333"),
			addr,
			control.BFD{Disable: &yes},
			"dummy",
		); err != nil {
			panic(err)
		}
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
		mustMakeDP(external, linkTypes, internal, internalNextHops, svc, local, neighbors, key),
	}
}

// NewDPRaw constructs a minimaly initialized DataPlane and returns it by reference. This is useful
// to non-internal tests that do not want any dataplane configuration beyond the strictly necessary.
// This is equivalent to router.newDataPlane, but returns an exported type.
func NewDPRaw(runConfig RunConfig, authSCMP bool) *DataPlane {

	edp := &DataPlane{
		makeDataPlane(runConfig, authSCMP),
	}
	return edp
}

func (d *DataPlane) MockStart() {
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
