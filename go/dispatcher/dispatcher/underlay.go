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
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
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
	if pkt.SCION.Path, err = pkt.SCION.Path.Reverse(); err != nil {
		return serrors.WrapStr("reversing path", err)
	}
	return nil
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

type Destination interface {
	// Send takes ownership of pkt, and then sends it to the location described
	// by this destination.
	Send(dp *NetToRingDataplane, pkt *respool.Packet)
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
