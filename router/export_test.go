// Copyright 2020 Anapaya Systems
// Copyright 2023 ETH Zurich
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

var metrics = NewMetrics()

func GetMetrics() *Metrics {
	return metrics
}

var NewServices = newServices

type Disposition disposition

const PDiscard = Disposition(pDiscard)

func NewPacket(raw []byte, src, dst *net.UDPAddr, ingress, egress uint16) *Packet {
	p := Packet{
		DstAddr:   &net.UDPAddr{IP: make(net.IP, 0, net.IPv6len)},
		srcAddr:   &net.UDPAddr{IP: make(net.IP, 0, net.IPv6len)},
		rawPacket: make([]byte, len(raw)),
		ingress:   ingress,
		egress:    egress,
	}

	if src != nil {
		p.srcAddr = src
	}
	if dst != nil {
		p.DstAddr = dst
	}
	copy(p.rawPacket, raw)
	return &p
}

func NewDP(
	external []uint16,
	linkTypes map[uint16]topology.LinkType,
	internal BatchConn,
	internalNextHops map[uint16]netip.AddrPort,
	svc map[addr.SVC][]netip.AddrPort,
	local addr.IA,
	neighbors map[uint16]addr.IA,
	key []byte) *DataPlane {

	dp := &DataPlane{
		underlay:            newUnderlay(),
		interfaces:          make(map[uint16]Link),
		localIA:             local,
		linkTypes:           linkTypes,
		neighborIAs:         neighbors,
		dispatchedPortStart: uint16(dispatchedPortStart),
		dispatchedPortEnd:   uint16(dispatchedPortEnd),
		svc:                 &services{m: svc},
		internalIP:          netip.MustParseAddr("198.51.100.1"),
		Metrics:             metrics,
	}

	dp.interfaces[0] = dp.underlay.NewInternalLink(internal, 64)

	// Make dummy external interfaces, as requested by the test. They are not actually used to send
	// or receive. The blank address might cause issues, though.
	for _, i := range external {
		dp.interfaces[i] = dp.underlay.NewExternalLink(nil, 64, nil, netip.AddrPort{}, i)
	}

	// Make dummy sibling interfaces, as requestes by the test.
	for i, addr := range internalNextHops {
		dp.interfaces[i] = dp.underlay.NewSiblingLink(64, nil, addr)
	}

	if err := dp.SetKey(key); err != nil {
		panic(err)
	}
	dp.initMetrics()
	return dp
}

func (d *DataPlane) FakeStart() {
	d.setRunning()
}

func (d *DataPlane) ProcessPkt(pkt *Packet) Disposition {

	p := newPacketProcessor(d)
	disp := p.processPkt(pkt)
	// Erase trafficType; we don't set it in the expected results.
	pkt.trafficType = ttOther
	return Disposition(disp)
}

func ExtractServices(s *services) map[addr.SVC][]netip.AddrPort {
	return s.m
}
