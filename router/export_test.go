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
	"fmt"
	"net"
	"net/netip"

	"github.com/golang/mock/gomock"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/ptr"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/router/bfd"
	"github.com/scionproto/scion/router/control"
	"github.com/scionproto/scion/router/mock_router"
)

var (
	dispatchedPortStart = 1024
	dispatchedPortEnd   = 1<<16 - 1
)

func GetMetrics() *Metrics {
	return metrics
}

type Disposition disposition

const PDiscard = Disposition(pDiscard)

// Implements the link interface minimally
type MockLink struct {
	ifID uint16
}

func (l *MockLink) IsUp() bool                                           { return true }
func (l *MockLink) IfID() uint16                                         { return l.ifID }
func (l *MockLink) Scope() LinkScope                                     { return Internal }
func (l *MockLink) BFDSession() *bfd.Session                             { return nil }
func (l *MockLink) Resolve(p *Packet, host addr.Host, port uint16) error { return nil }
func (l *MockLink) Send(p *Packet) bool                                  { return true }
func (l *MockLink) SendBlocking(p *Packet)                               {}

var _ Link = new(MockLink)

func newMockLink(ingress uint16) Link { return &MockLink{ifID: ingress} }

// NewPacket makes a mock packet. It has one shortcoming which makes it unsuited for some tests: The
// packet buffer is strictly no bigger than the supplied bytes; which means that it cannot be used
// to respond via SCMP. Also, it refers to a mock link that has the scope Internal in all cases.
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

// MockConnNewer implements the udpip ConnNewer interface with a method that returns a mock
// connection for testing purposes. An instance of this ConnNewer can be installed in a dataplane
// by way of the SetConnNewer method, exported here by the Dataplane type, or by way of
// dp.underlays[underlay].SetConnNewer(newer) for internal tests that use the dataPlane type.
type MockConnNewer struct {
	Ctrl *gomock.Controller
	Conn BatchConn
}

// New returns a BatchConn as the udpip underlay might have. If the field conn is non-nil, then that
// is what New returns. That enables tests to supply a specific BatchConn implementation. Else new
// returns an instance of MockBatchConn that is just a placeholder; calling any of the methods will
// cause the test to fail.
func (m MockConnNewer) New(l netip.AddrPort, r netip.AddrPort, c *conn.Config) (BatchConn, error) {
	var bc BatchConn
	if m.Conn != nil {
		return m.Conn, nil
	}
	bc = mock_router.NewMockBatchConn(m.Ctrl)
	return bc, nil
}

// mustMakeDP initializes a dataplane structure configured per the test requirements.
// External interfaces are given arbitrary addresses in the range 203.0.113/24 block and
// are not meant to actually carry traffic. The underlying connection is the same as
// the internal one, just to satisfy constraints.
func mustMakeDP(
	external []uint16,
	linkTypes map[uint16]topology.LinkType,
	connNewer any, // Some implementation of BatchConnNewer, or nil for the default.
	internalNextHops map[uint16]netip.AddrPort,
	local addr.IA,
	neighbors map[uint16]addr.IA,
	key []byte) (dp dataPlane) {

	dp = makeDataPlane(RunConfig{NumProcessors: 1, BatchSize: 64}, false)

	if err := dp.SetIA(local); err != nil {
		panic(err)
	}
	for i, n := range neighbors {
		if err := dp.AddNeighborIA(i, n); err != nil {
			panic(err)
		}
	}
	dp.SetPortRange(uint16(dispatchedPortStart), uint16(dispatchedPortEnd))

	if connNewer == nil {
		dp.underlays["udpip"].SetConnNewer(MockConnNewer{})
	} else {
		dp.underlays["udpip"].SetConnNewer(connNewer)
	}

	// Make dummy interfaces, as requested by the test. Only the internal interface is ever used to
	// send or receive and then, not always. The external interfaces are given non-zero
	// addresses in order to satisfy constraints.
	if err := dp.AddInternalInterface(netip.MustParseAddrPort("198.51.100.1:3333")); err != nil {
		panic(err)
	}
	l := control.LinkEnd{
		IA:   addr.MustParseIA("1-ff00:0:1"),
		Addr: "203.0.113.0:3333",
	}
	lh := addr.HostIP(netip.MustParseAddrPort(l.Addr).Addr())
	nobfd := control.BFD{Disable: ptr.To(true)}
	for _, i := range external {
		r := control.LinkEnd{
			IA:   addr.MustParseIA("1-ff00:0:3"),
			Addr: fmt.Sprintf("203.0.113.%d:3333", i),
		}
		rh := addr.HostIP(netip.MustParseAddrPort(r.Addr).Addr())
		link := control.LinkInfo{
			Provider: "udpip",
			Local:    l,
			Remote:   r,
			BFD:      nobfd,
			LinkTo:   linkTypes[i],
		}
		if err := dp.AddExternalInterface(i, link, lh, rh); err != nil {
			panic(err)
		}
	}

	l = control.LinkEnd{
		IA:   addr.MustParseIA("1-ff00:0:1"),
		Addr: "198.51.100.1:3333",
	}
	lh = addr.HostIP(netip.MustParseAddrPort(l.Addr).Addr())
	for i, a := range internalNextHops {
		r := control.LinkEnd{
			IA:   addr.MustParseIA(fmt.Sprintf("1-ff00:0:%d", 3+i)),
			Addr: a.String(),
		}
		rh := addr.HostIP(netip.MustParseAddrPort(r.Addr).Addr())
		link := control.LinkInfo{
			Provider: "udpip",
			Local:    l,
			Remote:   r,
			BFD:      nobfd,
			LinkTo:   linkTypes[i],
		}
		if err := dp.AddNextHop(i, link, lh, rh); err != nil {
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

// newDP constructs a dataPlane structure with mustMakeDP and returns it by reference. It
// returns a pointer to the unexported type, which is usable by internal tests.
func newDP(
	external []uint16,
	linkTypes map[uint16]topology.LinkType,
	connNewer any, // Some implementation of BatchConnNewer, or nil for the default.
	internalNextHops map[uint16]netip.AddrPort,
	local addr.IA,
	neighbors map[uint16]addr.IA,
	key []byte) *dataPlane {

	dp := mustMakeDP(external, linkTypes, connNewer, internalNextHops, local, neighbors, key)
	return &dp
}

// dataPlane is a dataplane structure as an exported type for use by non-internal tests.
type DataPlane struct {
	dataPlane
}

// NewDP constructs a DataPlane structure with mustMakeDP and returns it by reference. It
// returns a pointer to the exported type, which is usable by non-internal tests. A couple of
// methods are added to the exported type.
func NewDP(
	external []uint16,
	linkTypes map[uint16]topology.LinkType,
	connNewer any, // Some implementation of BatchConnNewer, or nil for the default.
	internalNextHops map[uint16]netip.AddrPort,
	local addr.IA,
	neighbors map[uint16]addr.IA,
	key []byte) *DataPlane {

	return &DataPlane{
		mustMakeDP(external, linkTypes, connNewer, internalNextHops, local, neighbors, key),
	}
}

// NewDPRaw constructs a minimally initialized DataPlane and returns it by reference. This is useful
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

func ExtractServices(s *Services[netip.AddrPort]) map[addr.SVC][]netip.AddrPort {
	return s.m
}

// We cannot know which tests are going to mock which underlay and what the newer's
// signature is. So we'll let the underlay implementation type-assert it.
func (dp *DataPlane) SetConnNewer(underlay string, newer any) {
	dp.underlays[underlay].SetConnNewer(newer)
}
