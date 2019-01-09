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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spkt"
)

const (
	ErrUnsupportedL4              = "unsupported SCION L4 protocol"
	ErrUnsupportedDestination     = "unsupported destination address type"
	ErrUnsupportedSCMPDestination = "unsupported SCMP destination address type"
	ErrUnsupportedQuotedL4Type    = "unsupported quoted L4 protocol type"
	ErrMalformedL4Quote           = "malformed L4 quote"
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
			log.Warn("error parsing incoming SCION packet", "err", err)
			continue
		}

		d, err := ComputeDestination(&pkt.Info)
		if err != nil {
			log.Warn("unable to route packet", "err", err)
			continue
		}
		d.Send(dp, pkt)
	}
}

func ComputeDestination(packet *spkt.ScnPkt) (Destination, error) {
	switch header := packet.L4.(type) {
	case *l4.UDP:
		return HandleUDP(packet, header)
	case *scmp.Hdr:
		return HandleSCMP(packet, header)
	default:
		return nil, common.NewBasicError(ErrUnsupportedL4, nil, "type", header.L4Type())
	}
}

func HandleUDP(packet *spkt.ScnPkt, header *l4.UDP) (Destination, error) {
	switch packet.DstHost.Type() {
	case addr.HostTypeIPv4, addr.HostTypeIPv6:
		return &UDPDestination{IP: packet.DstHost.IP(), Port: int(header.DstPort)}, nil
	case addr.HostTypeSVC:
		return SVCDestination(packet.DstHost.(addr.HostSVC)), nil
	default:
		return nil, common.NewBasicError(ErrUnsupportedDestination, nil,
			"type", packet.DstHost.Type())
	}
}

func HandleSCMP(packet *spkt.ScnPkt, header *scmp.Hdr) (Destination, error) {
	if packet.DstHost.Type() != addr.HostTypeIPv4 && packet.DstHost.Type() != addr.HostTypeIPv6 {
		return nil, common.NewBasicError(ErrUnsupportedSCMPDestination, nil,
			"type", packet.DstHost.Type())
	}
	if header.Class == scmp.C_General {
		return HandleSCMPGeneral(packet, header)
	} else {
		return HandleSCMPError(packet, header)
	}
}

func HandleSCMPGeneral(s *spkt.ScnPkt, header *scmp.Hdr) (Destination, error) {
	info := s.Pld.(*scmp.Payload).Info
	switch header.Type {
	case scmp.T_G_EchoReply:
		infoEcho := info.(*scmp.InfoEcho)
		return &SCMPGeneralAppDestination{IP: s.DstHost.IP(), ID: infoEcho.Id}, nil
	case scmp.T_G_RecordPathReply:
		infoRecordPath := info.(*scmp.InfoRecordPath)
		return &SCMPGeneralAppDestination{IP: s.DstHost.IP(), ID: infoRecordPath.Id}, nil
	case scmp.T_G_TraceRouteReply:
		infoTraceRoute := info.(*scmp.InfoTraceRoute)
		return &SCMPGeneralAppDestination{IP: s.DstHost.IP(), ID: infoTraceRoute.Id}, nil
	}
	return SCMPGeneralHandlerDestination{}, nil
}

func HandleSCMPError(packet *spkt.ScnPkt, header *scmp.Hdr) (Destination, error) {
	scmpPayload := packet.Pld.(*scmp.Payload)
	if scmpPayload.Meta.L4Proto != common.L4UDP {
		return nil, common.NewBasicError(ErrUnsupportedQuotedL4Type, nil,
			"type", scmpPayload.Meta.L4Proto)
	}
	quotedUDPHeader, err := l4.UDPFromRaw(scmpPayload.L4Hdr)
	if err != nil {
		return nil, common.NewBasicError(ErrMalformedL4Quote, nil, "err", err)
	}
	return &UDPDestination{IP: packet.DstHost.IP(), Port: int(quotedUDPHeader.SrcPort)}, nil
}

type Destination interface {
	Send(dp *NetToRingDataplane, pkt *Packet)
}

var _ Destination = (*UDPDestination)(nil)

type UDPDestination net.UDPAddr

func (d *UDPDestination) Send(dp *NetToRingDataplane, pkt *Packet) {
	item, ok := dp.RoutingTable.LookupPublic(pkt.Info.DstIA, (*net.UDPAddr)(d))
	if !ok {
		log.Warn("destination address not found", "ia", pkt.Info.DstIA,
			"udpAddr", (*net.UDPAddr)(d))
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

var _ Destination = SVCDestination(addr.SvcNone)

type SVCDestination addr.HostSVC

func (d SVCDestination) Send(dp *NetToRingDataplane, pkt *Packet) {
	// FIXME(scrye): This should deliver to the correct IP address, based on
	// information found in the overlay IP header.
	items := dp.RoutingTable.LookupService(pkt.Info.DstIA, addr.HostSVC(d), nil)
	if len(items) == 0 {
		log.Warn("destination address not found", "ia", pkt.Info.DstIA, "svc", d)
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

var _ Destination = (*SCMPGeneralAppDestination)(nil)

type SCMPGeneralAppDestination struct {
	IP net.IP
	ID uint64
}

func (d *SCMPGeneralAppDestination) Send(dp *NetToRingDataplane, pkt *Packet) {
	// FIXME(scrye): Implement this
	panic("not implemented")
}

var _ Destination = (*SCMPGeneralHandlerDestination)(nil)

type SCMPGeneralHandlerDestination struct{}

func (h SCMPGeneralHandlerDestination) Send(dp *NetToRingDataplane, pkt *Packet) {
	// FIXME(scrye): Implement this
	panic("not implemented")
}
