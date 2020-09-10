// Copyright 2020 Anapaya Systems

package router

import (
	"net"

	"github.com/google/gopacket"
	"golang.org/x/net/ipv4"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/slayers"
)

func NewDP(
	e map[uint16]BatchConn,
	i BatchConn,
	iNextHops map[uint16]net.Addr,
	svc map[addr.HostSVC][]net.Addr,
	local addr.IA,
	key []byte) *DataPlane {

	dp := &DataPlane{
		localIA:          local,
		external:         e,
		internalNextHops: iNextHops,
		svc:              svc,
		internal:         i,
	}
	dp.SetKey(key)
	return dp
}

func (d *DataPlane) FakeStart() {
	d.running = true
}

func (d *DataPlane) ProcessPkt(ifID uint16, m *ipv4.Message, s slayers.SCION,
	origPacket []byte, b gopacket.SerializeBuffer) (BatchConn, error) {
	return d.processPkt(ifID, m, s, origPacket, b)
}
