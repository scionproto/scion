// Copyright 2018 ETH Zurich
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

package network

import (
	"net"

	"github.com/scionproto/scion/go/godispatcher/internal/registration"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
)

// NetToRingDataplane reads SCION packets from the overlay socket, routes them
// to determine the destination process, and then enqueues the packets on the
// application's ingress ring.
//
// The rings are used to provide non-blocking IO for the overlay receiver.
type NetToRingDataplane struct {
	OverlayConn  net.PacketConn
	RoutingTable registration.IATable
}

func (dp *NetToRingDataplane) Run() error {
	for {
		pkt := NewPacket()
		pkt.Data = pkt.buffer

		n, readExtra, err := dp.OverlayConn.ReadFrom(pkt.Data)
		if err != nil {
			return err
		}
		pkt.Data = pkt.Data[:n]
		pkt.OverlayRemote = readExtra.(*net.UDPAddr)

		if err := hpkt.ParseScnPkt(&pkt.Info, pkt.Data); err != nil {
			log.Warn("error parsing SCION packet", "err", err)
			continue
		}

		switch pkt.Info.DstHost.Type() {
		case addr.HostTypeIPv4, addr.HostTypeIPv6:
			dp.deliverNormalPkt(pkt)
		case addr.HostTypeSVC:
			dp.deliverServicePkt(pkt)
		default:
			log.Warn("bad SCION destination address", pkt.Info.DstHost)
		}
	}
}

func (dp *NetToRingDataplane) deliverNormalPkt(pkt *Packet) {
	udpHeader, ok := pkt.Info.L4.(*l4.UDP)
	if !ok {
		log.Warn("got non SCION/UDP packet")
		return
	}
	udpAddr := &net.UDPAddr{
		IP:   pkt.Info.DstHost.IP(),
		Port: int(udpHeader.DstPort),
	}
	item, ok := dp.RoutingTable.LookupPublic(pkt.Info.DstIA, udpAddr)
	if !ok {
		log.Warn("destination address not found", "ia", pkt.Info.DstIA, "udpAddr", udpAddr)
		return
	}
	entry := item.(*TableEntry)
	// Move packet reference to other goroutine.
	count, _ := entry.appIngressRing.Write(ringbuf.EntryList{pkt}, false)
	if count <= 0 {
		// Release buffer if we couldn't transmit it to the other goroutine.
		pkt.Free()
	}
}

func (dp *NetToRingDataplane) deliverServicePkt(pkt *Packet) {
	svc := pkt.Info.DstHost.(addr.HostSVC)
	// FIXME(scrye): This should deliver to the correct IP address, based on
	// information found in the overlay IP header.
	items := dp.RoutingTable.LookupService(pkt.Info.DstIA, svc, nil)
	if len(items) == 0 {
		log.Warn("destination address not found", "ia", pkt.Info.DstIA, "svc", svc)
		return
	}
	for _, item := range items {
		pkt.Dup()
		entry := item.(*TableEntry)
		count, _ := entry.appIngressRing.Write(ringbuf.EntryList{pkt}, false)
		if count <= 0 {
			// Release buffer if we didn't write it
			pkt.Free()
		}
	}
	// Free our own reference to the packet.
	pkt.Free()
}
