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
	"unsafe"

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
func (l *MockLink) Metrics() *InterfaceMetrics                           { return nil }
func (l *MockLink) Scope() LinkScope                                     { return Internal }
func (l *MockLink) BFDSession() *bfd.Session                             { return nil }
func (l *MockLink) Resolve(p *Packet, host addr.Host, port uint16) error { return nil }
func (l *MockLink) Send(p *Packet) bool                                  { return true }
func (l *MockLink) SendBlocking(p *Packet)                               {}

var _ Link = new(MockLink)

func newMockLink(ingress uint16) Link { return &MockLink{ifID: ingress} }

// NewPacket makes a mock packet. It has shortcomings which makes it unsuited for some tests: it
// refers to a mock link that has the scope Internal in all cases, and a blank remote address.
func NewPacket(raw []byte, src, dst *net.UDPAddr, ingress, egress uint16) *Packet {
	pktBuf := &([bufSize]byte{})
	p := Packet{
		buffer:     pktBuf,
		RawPacket:  pktBuf[minHeadroom:],
		egress:     egress,
		Link:       newMockLink(ingress),
	}
	if src != nil {
		p.RemoteAddr = unsafe.Pointer(src)
	}
	if dst != nil {
		p.RemoteAddr = unsafe.Pointer(dst)
	}
	p.RawPacket = p.RawPacket[:len(raw)]
	copy(p.RawPacket, raw)
	return &p
}

// MockConnOpener implements the udpip ConnOpener interface with a method that returns a mock
// connection for testing purposes. An instance of this ConnOpener can be installed in a dataplane
// by way of the SetConnOpener method, exported here by the Dataplane type, or by way of
// dp.underlays[underlay].SetConnOpener(newer) for internal tests that use the dataPlane type.
type MockConnOpener struct {
	Ctrl *gomock.Controller
	Conn BatchConn
}

// New returns a BatchConn as the udpip underlay might have. If the field conn is non-nil, then that
// is what New returns. That enables tests to supply a specific BatchConn implementation. Else new
// returns an instance of MockBatchConn that is just a placeholder; calling any of the methods will
// cause the test to fail.
func (m MockConnOpener) Open(
	l netip.AddrPort, r netip.AddrPort, c *conn.Config) (BatchConn, error) {

	var bc BatchConn
	if m.Conn != nil {
		return m.Conn, nil
	}
	bc = mock_router.NewMockBatchConn(m.Ctrl)
	return bc, nil
}

func (m MockConnOpener) UDPCanReuseLocal() bool {
	// We let the udpip underlay create distinct connections for sibling links as sharing a single
	// mock connection between internal and sibling links obscures tests.
	return true
}

// mustMakeDP initializes a dataplane structure configured per the test requirements.
// External interfaces are given arbitrary addresses in the range 203.0.113/24 block and
// are not meant to actually carry traffic. The underlying connection is the same as
// the internal one, just to satisfy constraints.
func mustMakeDP(
	external []uint16,
	linkTypes map[uint16]topology.LinkType,
	connOpener any, // Some implementation of BatchConnOpener, or nil for the default.
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

	if connOpener == nil {
		dp.underlays["udpip"].SetConnOpener(MockConnOpener{})
	} else {
		dp.underlays["udpip"].SetConnOpener(connOpener)
	}

	// Make dummy interfaces, as requested by the test.
	internalAddr := "198.51.100.1:3333"
	localHost := addr.HostIP(netip.MustParseAddrPort(internalAddr).Addr())
	if err := dp.AddInternalInterface(localHost, "udpip", internalAddr); err != nil {
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
	connOpener any, // Some implementation of BatchConnOpener, or nil for the default.
	internalNextHops map[uint16]netip.AddrPort,
	local addr.IA,
	neighbors map[uint16]addr.IA,
	key []byte) *dataPlane {

	dp := mustMakeDP(external, linkTypes, connOpener, internalNextHops, local, neighbors, key)
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
	connOpener any, // Some implementation of BatchConnOpener, or nil for the default.
	internalNextHops map[uint16]netip.AddrPort,
	local addr.IA,
	neighbors map[uint16]addr.IA,
	key []byte) *DataPlane {

	return &DataPlane{
		mustMakeDP(external, linkTypes, connOpener, internalNextHops, local, neighbors, key),
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

// We cannot know which tests are going to mock which underlay and what the opener's
// signature is. So we'll let the underlay implementation type-assert it.
func (dp *DataPlane) SetConnOpener(underlay string, opener any) {
	dp.underlays[underlay].SetConnOpener(opener)
}
