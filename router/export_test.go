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

	"golang.org/x/net/ipv4"

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

var SlowPathRequired error = slowPathRequired

// Export the Packet struct so dataplane test can call ProcessPkt
type Packet struct {
	packet
}

func NewPacket(msg *ipv4.Message, ifId uint16) *Packet {
	// Pretend this is coming from the receiver.
	p := Packet{
		packet: packet{
			dstAddr: &net.UDPAddr{IP: make(net.IP, 0, net.IPv6len)},
			ingress: ifId,
		},
	}
	// nil happens *only* in test cases.
	if msg.Addr != nil {
		p.srcAddr = msg.Addr.(*net.UDPAddr)
	}
	p.rawPacket = p.packetBytes[:msg.N]
	copy(p.rawPacket, msg.Buffers[0])
	return &p
}

func (p *Packet) GetDestAddr() *net.UDPAddr {
	return p.packet.dstAddr
}

func (p *Packet) GetEgress() uint16 {
	return p.packet.egress
}

// Returns an ipv4Msg laid out like the forwarder would before calling writeBatch.
func (p *Packet) ToIpv4Msg() *ipv4.Message {
	msg := ipv4.Message{
		Buffers: [][]byte{p.rawPacket},
	}
	// processPkt never sets dstAddr to nil as that would cause the object to hit the garbage pile.
	// It makes its IP zero-lengthed. However, when translating to ipv4Msg we do translate that to
	// nil. Match this behaviour as the test expects ipv4Msgs that look exactly like those output by
	// the forwarder.
	msg.Addr = nil
	if len(p.dstAddr.IP) != 0 {
		msg.Addr = p.dstAddr
	}
	return &msg
}

func NewDP(
	external map[uint16]BatchConn,
	linkTypes map[uint16]topology.LinkType,
	internal BatchConn,
	internalNextHops map[uint16]*netip.AddrPort,
	svc map[addr.SVC][]netip.AddrPort,
	local addr.IA,
	neighbors map[uint16]addr.IA,
	key []byte) *DataPlane {

	dp := &DataPlane{
		localIA:             local,
		external:            external,
		linkTypes:           linkTypes,
		neighborIAs:         neighbors,
		internalNextHops:    internalNextHops,
		dispatchedPortStart: uint16(dispatchedPortStart),
		dispatchedPortEnd:   uint16(dispatchedPortEnd),
		svc:                 &services{m: svc},
		internal:            internal,
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
	d.running = true
}

func (d *DataPlane) ProcessPkt(pkt *Packet) error {

	p := newPacketProcessor(d)
	err := p.processPkt(&(pkt.packet))
	return err
}

func ExtractServices(s *services) map[addr.SVC][]netip.AddrPort {
	return s.m
}
