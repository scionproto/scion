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

package dispatcher

import (
	"net"

	"github.com/scionproto/scion/go/dispatcher/internal/metrics"
	"github.com/scionproto/scion/go/dispatcher/internal/respool"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spkt"
)

const (
	ErrUnsupportedL4              common.ErrMsg = "unsupported SCION L4 protocol"
	ErrUnsupportedDestination     common.ErrMsg = "unsupported destination address type"
	ErrUnsupportedSCMPDestination common.ErrMsg = "unsupported SCMP destination address type"
	ErrUnsupportedQuotedL4Type    common.ErrMsg = "unsupported quoted L4 protocol type"
	ErrMalformedL4Quote           common.ErrMsg = "malformed L4 quote"
)

// NetToRingDataplane reads SCION packets from the underlay socket, routes them
// to determine the destination process, and then enqueues the packets on the
// application's ingress ring.
//
// The rings are used to provide non-blocking IO for the underlay receiver.
type NetToRingDataplane struct {
	UnderlayConn net.PacketConn
	RoutingTable *IATable
}

func (dp *NetToRingDataplane) Run() error {
	for {
		pkt := respool.GetPacket()
		// XXX(scrye): we don't release the reference on error conditions, and
		// let the GC take care of this situation as they should be fairly
		// rare.

		if err := pkt.DecodeFromConn(dp.UnderlayConn); err != nil {
			log.Warn("error receiving next packet from underlay conn", "err", err)
			continue
		}

		logDebugE2E(&pkt.Info)

		dst, err := ComputeDestination(&pkt.Info)
		if err != nil {
			log.Warn("unable to route packet", "err", err)
			metrics.M.NetReadPkts(
				metrics.IncomingPacket{Result: metrics.PacketResultRouteNotFound},
			).Inc()
			continue
		}
		metrics.M.NetReadPkts(metrics.IncomingPacket{Result: metrics.PacketResultOk}).Inc()
		dst.Send(dp, pkt)
	}
}

func ComputeDestination(packet *spkt.ScnPkt) (Destination, error) {
	switch header := packet.L4.(type) {
	case *l4.UDP:
		return ComputeUDPDestination(packet, header)
	case *scmp.Hdr:
		return ComputeSCMPDestination(packet, header)
	default:
		return nil, common.NewBasicError(ErrUnsupportedL4, nil, "type", header.L4Type())
	}
}

func ComputeUDPDestination(packet *spkt.ScnPkt, header *l4.UDP) (Destination, error) {
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

// ComputeSCMPDestination decides which application to send the SCMP packet to. It also increments
// SCMP-related metrics.
func ComputeSCMPDestination(packet *spkt.ScnPkt, header *scmp.Hdr) (Destination, error) {
	metrics.M.SCMPReadPkts(
		metrics.SCMP{
			Class: header.Class.String(),
			Type:  header.Type.Name(header.Class),
		},
	).Inc()
	if packet.DstHost.Type() != addr.HostTypeIPv4 && packet.DstHost.Type() != addr.HostTypeIPv6 {
		return nil, common.NewBasicError(ErrUnsupportedSCMPDestination, nil,
			"type", packet.DstHost.Type())
	}
	if header.Class == scmp.C_General {
		return ComputeSCMPGeneralDestination(packet, header)
	} else {
		return ComputeSCMPErrorDestination(packet, header)
	}
}

func ComputeSCMPGeneralDestination(s *spkt.ScnPkt, header *scmp.Hdr) (Destination, error) {
	id := getSCMPGeneralID(s)
	if id == 0 {
		return nil, common.NewBasicError("Invalid SCMP ID", nil, "id", id)
	}
	switch {
	case isSCMPGeneralRequest(header):
		invertSCMPGeneralType(header)
		return SCMPHandlerDestination{}, nil
	case isSCMPGeneralReply(header):
		return &SCMPAppDestination{ID: id}, nil
	default:
		return nil, common.NewBasicError("Unsupported SCMP General type", nil, "type", header.Type)
	}
}

func ComputeSCMPErrorDestination(packet *spkt.ScnPkt, header *scmp.Hdr) (Destination, error) {
	scmpPayload := packet.Pld.(*scmp.Payload)
	switch scmpPayload.Meta.L4Proto {
	case common.L4UDP:
		quotedUDPHeader, err := l4.UDPFromRaw(scmpPayload.L4Hdr)
		if err != nil {
			return nil, common.NewBasicError(ErrMalformedL4Quote, nil, "err", err)
		}
		return &UDPDestination{IP: packet.DstHost.IP(), Port: int(quotedUDPHeader.SrcPort)}, nil
	case common.L4SCMP:

		id, err := getQuotedSCMPGeneralID(scmpPayload)
		if id == 0 {
			return nil, common.NewBasicError(ErrMalformedL4Quote, err)
		}
		return &SCMPAppDestination{ID: id}, nil
	default:
		return nil, common.NewBasicError(ErrUnsupportedQuotedL4Type, nil,
			"type", scmpPayload.Meta.L4Proto)
	}
}

type Destination interface {
	// Send takes ownership of pkt, and then sends it to the location described
	// by this destination.
	Send(dp *NetToRingDataplane, pkt *respool.Packet)
}

var _ Destination = (*UDPDestination)(nil)

type UDPDestination net.UDPAddr

func (d *UDPDestination) Send(dp *NetToRingDataplane, pkt *respool.Packet) {
	routingEntry, ok := dp.RoutingTable.LookupPublic(pkt.Info.DstIA, (*net.UDPAddr)(d))
	if !ok {
		metrics.M.AppNotFoundErrors().Inc()
		log.Warn("destination address not found", "ia", pkt.Info.DstIA,
			"udpAddr", (*net.UDPAddr)(d))
		return
	}
	sendPacket(routingEntry, pkt)
}

var _ Destination = SVCDestination(addr.SvcNone)

type SVCDestination addr.HostSVC

func (d SVCDestination) Send(dp *NetToRingDataplane, pkt *respool.Packet) {
	// FIXME(scrye): This should deliver to the correct IP address, based on
	// information found in the underlay IP header.
	routingEntries := dp.RoutingTable.LookupService(pkt.Info.DstIA, addr.HostSVC(d), nil)
	if len(routingEntries) == 0 {
		metrics.M.AppNotFoundErrors().Inc()
		log.Warn("destination address not found", "ia", pkt.Info.DstIA, "svc", addr.HostSVC(d))
		return
	}
	// Increase reference count for all extra copies
	for i := 0; i < len(routingEntries)-1; i++ {
		pkt.Dup()
	}
	for _, routingEntry := range routingEntries {
		metrics.M.AppWriteSVCPkts(metrics.SVC{Type: addr.HostSVC(d).String()}).Inc()
		sendPacket(routingEntry, pkt)
	}
}

var _ Destination = (*SCMPAppDestination)(nil)

type SCMPAppDestination struct {
	ID uint64
}

func (d *SCMPAppDestination) Send(dp *NetToRingDataplane, pkt *respool.Packet) {
	routingEntry, ok := dp.RoutingTable.LookupID(pkt.Info.DstIA, d.ID)
	if !ok {
		metrics.M.AppNotFoundErrors().Inc()
		log.Warn("destination address not found", "SCMP", d.ID)
		return
	}
	sendPacket(routingEntry, pkt)
}

// sendPacket puts pkt on the routing entry's ring buffer, and releases the
// reference to pkt.
func sendPacket(routingEntry *TableEntry, pkt *respool.Packet) {
	// Move packet reference to other goroutine.
	count, _ := routingEntry.appIngressRing.Write(ringbuf.EntryList{pkt}, false)
	if count <= 0 {
		// Release buffer if we couldn't transmit it to the other goroutine.
		pkt.Free()
	}
}

var _ Destination = (*SCMPHandlerDestination)(nil)

type SCMPHandlerDestination struct{}

func (h SCMPHandlerDestination) Send(dp *NetToRingDataplane, pkt *respool.Packet) {
	if err := pkt.Info.Reverse(); err != nil {
		log.Warn("Unable to reverse SCMP packet.", "err", err)
		return
	}

	b := respool.GetBuffer()
	pkt.Info.HBHExt = removeSCMPHBH(pkt.Info.HBHExt)
	n, err := hpkt.WriteScnPkt(&pkt.Info, b)
	if err != nil {
		log.Warn("Unable to create reply SCMP packet", "err", err)
		return
	}

	if scmpHdr, ok := pkt.Info.L4.(*scmp.Hdr); ok {
		// above ok should always be true, because this handler only gets invoked when
		// replying to SCMP packets
		metrics.M.SCMPWritePkts(
			metrics.SCMP{
				Class: scmpHdr.Class.String(),
				Type:  scmpHdr.Type.Name(scmpHdr.Class),
			},
		).Inc()
	}

	_, err = dp.UnderlayConn.WriteTo(b[:n], pkt.UnderlayRemote)
	if err != nil {
		log.Warn("Unable to write to underlay socket.", "err", err)
		return
	}
	respool.PutBuffer(b)
	pkt.Free()
}

func logDebugE2E(pkt *spkt.ScnPkt) {
	for _, e := range pkt.E2EExt {
		if extnData, ok := e.(*layers.ExtnE2EDebug); ok {
			log.Trace("Recv'd packet with debug extension", "debug_id", extnData.ID, "pkt", pkt)
		}
	}
}
