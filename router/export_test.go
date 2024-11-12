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

// Export the Packet struct so dataplane test can call ProcessPkt
type Packet struct {
	packet
}

type Disposition disposition

const PDiscard = Disposition(pDiscard)

func NewPacket(raw []byte, src, dst *net.UDPAddr, ingress, egress uint16) *Packet {
	p := Packet{
		packet: packet{
			dstAddr:   &net.UDPAddr{IP: make(net.IP, 0, net.IPv6len)},
			srcAddr:   &net.UDPAddr{IP: make(net.IP, 0, net.IPv6len)},
			rawPacket: make([]byte, len(raw)),
			ingress:   ingress,
			egress:    egress,
		},
	}
	if src != nil {
		p.srcAddr = src
	}
	if dst != nil {
		p.dstAddr = dst
	}
	copy(p.rawPacket, raw)
	return &p
}

func NewDP(
	external map[uint16]BatchConn,
	linkTypes map[uint16]topology.LinkType,
	internal BatchConn,
	internalNextHops map[uint16]netip.AddrPort,
	svc map[addr.SVC][]netip.AddrPort,
	local addr.IA,
	neighbors map[uint16]addr.IA,
	key []byte) *DataPlane {

	dp := &DataPlane{
		interfaces:          map[uint16]BatchConn{0: internal},
		localIA:             local,
		external:            external,
		linkTypes:           linkTypes,
		neighborIAs:         neighbors,
		internalNextHops:    internalNextHops,
		dispatchedPortStart: uint16(dispatchedPortStart),
		dispatchedPortEnd:   uint16(dispatchedPortEnd),
		svc:                 &services{m: svc},
		internalIP:          netip.MustParseAddr("198.51.100.1"),
		Metrics:             metrics,
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
	disp := p.processPkt(&(pkt.packet))
	// Erase trafficType; we don't set it in the expected results.
	pkt.trafficType = ttOther
	return Disposition(disp)
}

func ExtractServices(s *services) map[addr.SVC][]netip.AddrPort {
	return s.m
}
