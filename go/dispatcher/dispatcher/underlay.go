// Copyright 2018 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/dispatcher/internal/metrics"
	"github.com/scionproto/scion/go/dispatcher/internal/respool"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
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
	// HeaderV2 indicates whether the new header format is used.
	HeaderV2 bool
}

func (dp *NetToRingDataplane) Run() error {
	if !dp.HeaderV2 {
		return dp.runLegacy()
	}
	for {
		pkt := respool.GetPacket(true)
		// XXX(scrye): we don't release the reference on error conditions, and
		// let the GC take care of this situation as they should be fairly
		// rare.

		if err := pkt.DecodeFromConn(dp.UnderlayConn); err != nil {
			log.Debug("error receiving next packet from underlay conn", "err", err)
			continue
		}
		dst, err := getDst(pkt)
		if err != nil {
			log.Debug("unable to route packet", "err", err)
			metrics.M.NetReadPkts(
				metrics.IncomingPacket{Result: metrics.PacketResultRouteNotFound},
			).Inc()
			continue
		}
		metrics.M.NetReadPkts(metrics.IncomingPacket{Result: metrics.PacketResultOk}).Inc()
		dst.Send(dp, pkt)
	}
}

func (dp *NetToRingDataplane) runLegacy() error {
	for {
		pkt := respool.GetPacket(dp.HeaderV2)
		// XXX(scrye): we don't release the reference on error conditions, and
		// let the GC take care of this situation as they should be fairly
		// rare.

		if err := pkt.DecodeFromConn(dp.UnderlayConn); err != nil {
			log.Debug("error receiving next packet from underlay conn", "err", err)
			continue
		}

		dst, err := ComputeDestination(&pkt.Info)
		if err != nil {
			log.Debug("unable to route packet", "err", err)
			metrics.M.NetReadPkts(
				metrics.IncomingPacket{Result: metrics.PacketResultRouteNotFound},
			).Inc()
			continue
		}
		metrics.M.NetReadPkts(metrics.IncomingPacket{Result: metrics.PacketResultOk}).Inc()
		dst.Send(dp, pkt)
	}
}

func getDst(pkt *respool.Packet) (Destination, error) {
	switch pkt.L4 {
	case slayers.LayerTypeSCIONUDP:
		return getDstUDP(pkt)
	case slayers.LayerTypeSCMP:
		return getDstSCMP(pkt)
	default:
		return nil, serrors.WithCtx(ErrUnsupportedL4, "type", pkt.L4)
	}
}

func getDstUDP(pkt *respool.Packet) (Destination, error) {
	dst, err := pkt.SCION.DstAddr()
	if err != nil {
		return nil, err
	}
	switch d := dst.(type) {
	case *net.IPAddr:
		return UDPDestination{
			IA: pkt.SCION.DstIA,
			Public: &net.UDPAddr{
				IP:   d.IP,
				Port: int(pkt.UDP.DstPort),
			},
		}, nil
	case addr.HostSVC:
		return SVCDestination{
			IA:  pkt.SCION.DstIA,
			Svc: d,
		}, nil
	default:
		return nil, serrors.WithCtx(ErrUnsupportedDestination, "type", common.TypeOf(dst))
	}
}

func getDstSCMP(pkt *respool.Packet) (Destination, error) {
	if !pkt.SCMP.TypeCode.InfoMsg() {
		dst, err := getDstSCMPErr(pkt)
		if err != nil {
			return nil, serrors.WrapStr("delivering SCMP error message", err)
		}
		return dst, nil
	}
	return getDstSCMPInfo(pkt)
}

func getDstSCMPInfo(pkt *respool.Packet) (Destination, error) {
	t := pkt.SCMP.TypeCode.Type()
	if t == slayers.SCMPTypeEchoRequest || t == slayers.SCMPTypeTracerouteRequest {
		return SCMPHandler{}, nil
	}
	if t == slayers.SCMPTypeEchoReply || t == slayers.SCMPTypeTracerouteReply {
		id, err := extractSCMPIdentifier(&pkt.SCMP)
		if err != nil {
			return nil, err
		}
		return SCMPDestination{IA: pkt.SCION.DstIA, ID: id}, nil
	}
	return nil, serrors.New("unsupported SCMP info message", "type", t)
}

func getDstSCMPErr(pkt *respool.Packet) (Destination, error) {
	// Drop unknown SCMP error messages.
	if pkt.SCMP.NextLayerType() == gopacket.LayerTypePayload {
		return nil, serrors.New("unsupported SCMP error message", "type", pkt.SCMP.TypeCode.Type())
	}
	l, err := decodeSCMP(&pkt.SCMP)
	if err != nil {
		return nil, err
	}
	if len(l) != 2 {
		return nil, serrors.New("SCMP error message without payload")
	}
	gpkt := gopacket.NewPacket(*l[1].(*gopacket.Payload), slayers.LayerTypeSCION,
		gopacket.DecodeOptions{
			NoCopy: true,
		},
	)

	// If the offending packet was UDP/SCION, use the source port to deliver.
	if udp := gpkt.Layer(slayers.LayerTypeSCIONUDP); udp != nil {
		port := int(udp.(*slayers.UDP).SrcPort)
		// XXX(roosd): We assume that the zero value means the UDP header is
		// truncated. This flags packets of misbehaving senders as truncated, if
		// they set the source port to 0. But there is no harm, since those
		// packets are destined to be dropped anyway.
		if port == 0 {
			return nil, serrors.New("SCMP error with truncated UDP header")
		}
		dst, err := pkt.SCION.DstAddr()
		if err != nil {
			return nil, err
		}
		ipAddr, ok := dst.(*net.IPAddr)
		if !ok {
			return nil, serrors.WithCtx(ErrUnsupportedDestination, "type", common.TypeOf(dst))
		}
		return UDPDestination{
			IA: pkt.SCION.DstIA,
			Public: &net.UDPAddr{
				IP:   ipAddr.IP,
				Port: port,
			},
		}, nil
	}

	// If the offending packet was SCMP/SCION, and it is an echo or traceroute,
	// use the Identifier to deliver. In all other cases, the message is dropped.
	if scmp := gpkt.Layer(slayers.LayerTypeSCMP); scmp != nil {

		tc := scmp.(*slayers.SCMP).TypeCode
		// SCMP Error messages in response to an SCMP error message are not allowed.
		if !tc.InfoMsg() {
			return nil, serrors.New("SCMP error message in response to SCMP error message",
				"type", tc.Type())
		}
		// We only support echo and traceroute requests.
		t := tc.Type()
		if t != slayers.SCMPTypeEchoRequest && t != slayers.SCMPTypeTracerouteRequest {
			return nil, serrors.New("unsupported SCMP info message", "type", t)
		}

		var id uint16
		// Extract the ID from the echo or traceroute layer.
		if echo := gpkt.Layer(slayers.LayerTypeSCMPEcho); echo != nil {
			id = echo.(*slayers.SCMPEcho).Identifier
		} else if tr := gpkt.Layer(slayers.LayerTypeSCMPTraceroute); tr != nil {
			id = tr.(*slayers.SCMPTraceroute).Identifier
		} else {
			return nil, serrors.New("SCMP error with truncated payload")
		}
		return SCMPDestination{
			IA: pkt.SCION.DstIA,
			ID: id,
		}, nil
	}
	return nil, ErrUnsupportedL4
}

// UDPDestination delivers packets to the app that registered for the configured
// public address.
type UDPDestination struct {
	IA     addr.IA
	Public *net.UDPAddr
}

func (d UDPDestination) Send(dp *NetToRingDataplane, pkt *respool.Packet) {
	routingEntry, ok := dp.RoutingTable.LookupPublic(d.IA, d.Public)
	if !ok {
		metrics.M.AppNotFoundErrors().Inc()
		log.Debug("destination address not found", "isd_as", d.IA, "udp_addr", d.Public)
		return
	}
	sendPacket(routingEntry, pkt)
}

// SVCDestination delivers packets to apps that registered for the configured
// service.
type SVCDestination struct {
	IA  addr.IA
	Svc addr.HostSVC
}

func (d SVCDestination) Send(dp *NetToRingDataplane, pkt *respool.Packet) {
	// FIXME(scrye): This should deliver to the correct IP address, based on
	// information found in the underlay IP header.
	routingEntries := dp.RoutingTable.LookupService(d.IA, d.Svc, nil)
	if len(routingEntries) == 0 {
		metrics.M.AppNotFoundErrors().Inc()
		log.Debug("destination address not found", "isd_as", d.IA, "svc", d.Svc)
		return
	}
	// Increase reference count for all extra copies
	for i := 0; i < len(routingEntries)-1; i++ {
		pkt.Dup()
	}
	for _, routingEntry := range routingEntries {
		metrics.M.AppWriteSVCPkts(metrics.SVC{Type: d.Svc.String()}).Inc()
		sendPacket(routingEntry, pkt)
	}
}

type SCMPDestination struct {
	IA addr.IA
	ID uint16
}

func (d SCMPDestination) Send(dp *NetToRingDataplane, pkt *respool.Packet) {
	routingEntry, ok := dp.RoutingTable.LookupID(d.IA, uint64(d.ID))
	if !ok {
		metrics.M.AppNotFoundErrors().Inc()
		log.Debug("destination address not found", "SCMP", d.ID)
		return
	}
	sendPacket(routingEntry, pkt)
}

// SCMPHandler replies to SCMP echo and traceroute requests.
type SCMPHandler struct{}

func (h SCMPHandler) Send(dp *NetToRingDataplane, pkt *respool.Packet) {
	// FIXME(roosd): introduce metrics again.
	raw, err := h.reverse(pkt)
	if err != nil {
		log.Info("Failed to reverse SCMP packet, dropping", "err", err)
		return
	}
	_, err = dp.UnderlayConn.WriteTo(raw, pkt.UnderlayRemote)
	if err != nil {
		log.Info("Unable to write to underlay socket", "err", err)
		return
	}
	pkt.Free()
}

func (h SCMPHandler) reverse(pkt *respool.Packet) ([]byte, error) {
	l, err := decodeSCMP(&pkt.SCMP)
	if err != nil {
		return nil, err
	}
	// Translate request to a reply.
	switch l[0].LayerType() {
	case slayers.LayerTypeSCMPEcho:
		pkt.SCMP.TypeCode = slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoReply, 0)
	case slayers.LayerTypeSCMPTraceroute:
		pkt.SCMP.TypeCode = slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0)
	default:
		return nil, serrors.New("unsupported SCMP informational message")
	}
	if err := h.reverseSCION(pkt); err != nil {
		return nil, err
	}
	// FIXME(roosd): Consider moving this to a resource pool.
	buf := gopacket.NewSerializeBuffer()
	if err := pkt.SCMP.SetNetworkLayerForChecksum(&pkt.SCION); err != nil {
		return nil, err
	}
	err = gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		},
		append([]gopacket.SerializableLayer{&pkt.SCION, &pkt.SCMP}, l...)...,
	)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (h SCMPHandler) reverseSCION(pkt *respool.Packet) error {
	// Reverse the SCION packet.
	pkt.SCION.DstIA, pkt.SCION.SrcIA = pkt.SCION.SrcIA, pkt.SCION.DstIA
	src, err := pkt.SCION.SrcAddr()
	if err != nil {
		return serrors.WrapStr("parsing source address", err)
	}
	dst, err := pkt.SCION.DstAddr()
	if err != nil {
		return serrors.WrapStr("parsing destination address", err)
	}
	if err := pkt.SCION.SetSrcAddr(dst); err != nil {
		return serrors.WrapStr("setting source address", err)
	}
	if err := pkt.SCION.SetDstAddr(src); err != nil {
		return serrors.WrapStr("setting destination address", err)
	}
	if err := pkt.SCION.Path.Reverse(); err != nil {
		return serrors.WrapStr("reversing path", err)
	}
	return nil
}

func extractIP(dst net.Addr, err error) (net.IP, error) {
	if err != nil {
		return nil, err
	}
	ipAddr, ok := dst.(*net.IPAddr)
	if !ok {
		return nil, serrors.New("unsupported address", "type", common.TypeOf(dst))
	}
	return ipAddr.IP, nil
}

func extractSCMPIdentifier(scmp *slayers.SCMP) (uint16, error) {
	l, err := decodeSCMP(scmp)
	if err != nil {
		return 0, err
	}
	switch info := l[0].(type) {
	case *slayers.SCMPEcho:
		return info.Identifier, nil
	case *slayers.SCMPTraceroute:
		return info.Identifier, nil
	default:
		return 0, serrors.New("invalid SCMP info message", "type_code", scmp.TypeCode)
	}
}

// decodeSCMP decodes the SCMP payload. WARNING: Decoding is done with NoCopy set.
func decodeSCMP(scmp *slayers.SCMP) ([]gopacket.SerializableLayer, error) {
	gpkt := gopacket.NewPacket(scmp.Payload, scmp.NextLayerType(),
		gopacket.DecodeOptions{NoCopy: true})
	layers := gpkt.Layers()
	if len(layers) == 0 || len(layers) > 2 {
		return nil, serrors.New("invalid number of SCMP layers", "count", len(layers))
	}
	ret := make([]gopacket.SerializableLayer, len(layers))
	for i, l := range layers {
		s, ok := l.(gopacket.SerializableLayer)
		if !ok {
			return nil, serrors.New("invalid SCMP layer, not serializable", "index", i)
		}
		ret[i] = s
	}
	return ret, nil
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
		return &UDPDestinationLegacy{IP: packet.DstHost.IP(), Port: int(header.DstPort)}, nil
	case addr.HostTypeSVC:
		return SVCDestinationLegacy(packet.DstHost.(addr.HostSVC)), nil
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
		return SCMPHandlerDestination{HeaderV2: false}, nil
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
		return &UDPDestinationLegacy{
			IP:   packet.DstHost.IP(),
			Port: int(quotedUDPHeader.SrcPort),
		}, nil
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

var _ Destination = (*UDPDestinationLegacy)(nil)

type UDPDestinationLegacy net.UDPAddr

func (d *UDPDestinationLegacy) Send(dp *NetToRingDataplane, pkt *respool.Packet) {
	routingEntry, ok := dp.RoutingTable.LookupPublic(pkt.Info.DstIA, (*net.UDPAddr)(d))
	if !ok {
		metrics.M.AppNotFoundErrors().Inc()
		log.Debug("destination address not found", "ia", pkt.Info.DstIA,
			"udpAddr", (*net.UDPAddr)(d))
		return
	}
	sendPacket(routingEntry, pkt)
}

var _ Destination = SVCDestinationLegacy(addr.SvcNone)

type SVCDestinationLegacy addr.HostSVC

func (d SVCDestinationLegacy) Send(dp *NetToRingDataplane, pkt *respool.Packet) {
	// FIXME(scrye): This should deliver to the correct IP address, based on
	// information found in the underlay IP header.
	routingEntries := dp.RoutingTable.LookupService(pkt.Info.DstIA, addr.HostSVC(d), nil)
	if len(routingEntries) == 0 {
		metrics.M.AppNotFoundErrors().Inc()
		log.Debug("destination address not found", "ia", pkt.Info.DstIA, "svc", addr.HostSVC(d))
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
		log.Debug("destination address not found", "SCMP", d.ID)
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

type SCMPHandlerDestination struct {
	// HeaderV2 switches SCMP messages to the new SCION header format.
	HeaderV2 bool
}

func (h SCMPHandlerDestination) Send(dp *NetToRingDataplane, pkt *respool.Packet) {
	if err := pkt.Info.Reverse(); err != nil {
		log.Info("Unable to reverse SCMP packet.", "err", err)
		return
	}

	b := respool.GetBuffer()
	pkt.Info.HBHExt = removeSCMPHBH(pkt.Info.HBHExt)
	var n int
	var err error
	if h.HeaderV2 {
		n, err = hpkt.WriteScnPkt2(&pkt.Info, b)
	} else {
		n, err = hpkt.WriteScnPkt(&pkt.Info, b)
	}
	if err != nil {
		log.Info("Unable to create reply SCMP packet", "err", err)
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
		log.Info("Unable to write to underlay socket.", "err", err)
		return
	}
	respool.PutBuffer(b)
	pkt.Free()
}
