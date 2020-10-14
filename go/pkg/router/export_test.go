// Copyright 2020 Anapaya Systems

package router

import (
	"net"

	"github.com/google/gopacket"
	"golang.org/x/net/ipv4"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/underlay/conn"
)

var NewServices = newServices

func NewDP(
	external map[uint16]BatchConn,
	linkTypes map[uint16]topology.LinkType,
	internal BatchConn,
	internalNextHops map[uint16]net.Addr,
	svc map[addr.HostSVC][]*net.UDPAddr,
	local addr.IA,
	key []byte) *DataPlane {

	dp := &DataPlane{
		localIA:          local,
		external:         external,
		linkTypes:        linkTypes,
		internalNextHops: internalNextHops,
		svc:              &services{m: svc},
		internal:         internal,
	}
	dp.SetKey(key)
	return dp
}

func (d *DataPlane) FakeStart() {
	d.running = true
}

func (d *DataPlane) ProcessPkt(ifID uint16, m *ipv4.Message, meta conn.ReadMeta, s slayers.SCION,
	origPacket []byte, b gopacket.SerializeBuffer) (BatchConn, error) {
	return d.processPkt(ifID, m, meta, s, origPacket, b)
}

func ExtractServices(s *services) map[addr.HostSVC][]*net.UDPAddr {
	return s.m
}
