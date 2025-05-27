// Copyright 2025 SCION Association
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

package afpacketudpip

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/bfd"
)

type internalLink struct {
	procQs           []chan *router.Packet
	header           []byte
	egressQ          chan *router.Packet
	metrics          *router.InterfaceMetrics
	pool             router.PacketPool
	svc              *router.Services[netip.AddrPort]
	seed             uint32
	dispatchStart    uint16
	dispatchEnd      uint16
	dispatchRedirect uint16
	is4              bool
}

// Expensive. Call only to make a few prefab headers.
func (l *internalLink) packHeader(src *netip.AddrPort) {

	sb := gopacket.NewSerializeBuffer()
	ethernet := layers.Ethernet{
		// FIXME! We must get those from the interface and from ARP!
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x1, 0x1},
		DstMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x2, 0x2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(src.Port()),
	}
	l.is4 = src.Addr().Is4()

	if l.is4 {
		ip := layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			SrcIP:    src.Addr().AsSlice(),
			DstIP:    netip.IPv4Unspecified().AsSlice(),
			Protocol: layers.IPProtocolUDP,
			// Flags:    layers.IPv4DontFragment, // Sure about that?
		}
		_ = udp.SetNetworkLayerForChecksum(&ip)
		err := gopacket.SerializeLayers(sb, seropts, &ethernet, &ip, &udp)
		if err != nil {
			// The only possible reason for this is in the few lines above.
			panic("Cannot serialize static header")
		}

		// We have to truncate the result; gopacket is scared of generating a packet shorter than
		// the ethernet minimum.
		l.header = sb.Bytes()[:42]
		return
	}

	ip := layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolUDP,
		HopLimit:   64,
		SrcIP:      src.Addr().AsSlice(),
		DstIP:      netip.IPv6Unspecified().AsSlice(),
	}
	_ = udp.SetNetworkLayerForChecksum(&ip)
	err := gopacket.SerializeLayers(sb, seropts, &ethernet, &ip, &udp)
	if err != nil {
		// The only possible reason for this is in the few lines above.
		panic("Cannot serialize static header")
	}

	// We have to truncate the result; gopacket is scared of generating a packet shorter than the
	// ethernet minimum.
	l.header = sb.Bytes()[:62]
}

// FIXME: can do cleaner and more legible... and maybe faster.
func (l *internalLink) addHeader(p *router.Packet, dst *netip.AddrPort) {
	payloadLen := len(p.RawPacket)
	p.RawPacket = p.WithHeader(len(l.header))
	copy(p.RawPacket, l.header)

	// Inject dest
	copy(p.RawPacket, net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x2, 0x2})
	copy(p.RawPacket[14+16:], dst.Addr().AsSlice()) // Can do cheaper?
	binary.BigEndian.PutUint16(p.RawPacket[14+20+2:], dst.Port())

	if l.is4 {
		// Fix the IP total length field
		binary.BigEndian.PutUint16(p.RawPacket[14+2:], uint16(payloadLen)+20+8)

		// Update UDP length
		binary.BigEndian.PutUint16(p.RawPacket[14+20+4:], uint16(payloadLen)+8)

		// For IPv4 fix the IP checksum
		p.RawPacket[14+10] = 0
		p.RawPacket[14+11] = 0
		csum := gopacket.ComputeChecksum(p.RawPacket[14:14+20], 0)
		binary.BigEndian.PutUint16(p.RawPacket[14+10:], gopacket.FoldChecksum(csum))

		// For IPV4 we can screw the UDP checksum
		p.RawPacket[14+20+6] = 0
		p.RawPacket[14+20+7] = 0
		return
	}

	// Fix the IPv6 payload length field (udp plus the scion stuff)
	binary.BigEndian.PutUint16(p.RawPacket[14+4:], uint16(payloadLen)+8)

	// Update UDP length
	binary.BigEndian.PutUint16(p.RawPacket[14+40+4:], uint16(payloadLen)+8)

	// For IPV6 we must compute the UDP checksum.
	// In theory we could dispense with it as we're a tunneling protocol; however all the plain
	// udp underlay implementations would drop the packets.
	zerosAndProto := []byte{0, 0, 0, 17}
	csum := gopacket.ComputeChecksum(p.RawPacket[14+8:14+40], 0)        // src+dst
	csum = gopacket.ComputeChecksum(p.RawPacket[14+40+4:14+40+6], csum) // UDP length
	csum = gopacket.ComputeChecksum(zerosAndProto, csum)                // 3 0s plus UDP proto num
	binary.BigEndian.PutUint16(p.RawPacket[14+40+18:], gopacket.FoldChecksum(csum))
}

func (l *internalLink) start(
	ctx context.Context,
	procQs []chan *router.Packet,
	pool router.PacketPool,
) {
	// procQs and pool are never known before all configured links have been instantiated. So we
	// get them only now. We didn't need it earlier since the connections have not been started yet.
	l.procQs = procQs
	l.pool = pool
}

func (l *internalLink) stop() {
}

func (l *internalLink) IfID() uint16 {
	return 0
}

func (l *internalLink) Metrics() *router.InterfaceMetrics {
	return l.metrics
}

func (l *internalLink) Scope() router.LinkScope {
	return router.Internal
}

func (l *internalLink) BFDSession() *bfd.Session {
	return nil
}

func (l *internalLink) IsUp() bool {
	return true
}

// Resolve updates the packet's underlay destination according to the given SCION host/service
// address and SCION port number.  On the UDP/IP underlay, host addresses are bit-for-bit identical
// to underlay addresses. The port space is the same, except if the packet is redirected to the shim
// dispatcher.
func (l *internalLink) Resolve(p *router.Packet, dst addr.Host, port uint16) error {
	var dstAddr netip.Addr
	switch dst.Type() {
	case addr.HostTypeSVC:
		// For map lookup use the Base address, i.e. strip the multi cast information, because we
		// only register base addresses in the map.
		a, ok := l.svc.Any(dst.SVC().Base())
		if !ok {
			return router.ErrNoSVCBackend
		}
		dstAddr = a.Addr()
		// Supplied port is irrelevant. Port is in svc record.
		port = a.Port()
	case addr.HostTypeIP:
		dstAddr = dst.IP()
		if dstAddr.Is4In6() {
			return router.ErrUnsupportedV4MappedV6Address
		}
		if dstAddr.IsUnspecified() {
			return router.ErrUnsupportedUnspecifiedAddress
		}
	default:
		panic(fmt.Sprintf("unexpected address type returned from DstAddr: %s", dst.Type()))
	}
	// if port is outside the configured port range we send to the fixed port.
	if port < l.dispatchStart && port > l.dispatchEnd {
		port = l.dispatchRedirect
	}

	// Packets that get here must have come from an external or a sibling link; neither of which
	// attach a RemoteAddr to the packet (besides; it could be a different type). So, RemoteAddr is
	// not generally usable. We must allocate a new object. The precautions needed to pool them cost
	// more than the pool saves (verified experimentally).
	addrPort := netip.AddrPortFrom(dstAddr, port)
	p.RemoteAddr = unsafe.Pointer(&addrPort)

	return nil
}

func (l *internalLink) Send(p *router.Packet) bool {
	// TODO(jiceatscion): The packet's destination is in the packet's meta-data; it was put there by
	// Resolve() We need to craft a header in front of the packet.  May be resolve could do that,
	// instead of just storing the destination in the packet structure. That would save us the
	// allocation of address but requires some more changes to the dataplane code structure.
	l.addHeader(p, (*netip.AddrPort)(p.RemoteAddr))
	select {
	case l.egressQ <- p:
	default:
		return false
	}
	return true
}

func (l *internalLink) SendBlocking(p *router.Packet) {
	// Likewise: p.remoteAddress -> header.
	l.addHeader(p, (*netip.AddrPort)(p.RemoteAddr))
	l.egressQ <- p
}

// receive delivers an incoming packet to the appropriate processing queue.
// Because this link is not associated with a specific remote address, the src
// address of the packet is recorded in the packet structure. This may be used
// as the destination if SCMP responds.
func (l *internalLink) receive(srcAddr *netip.AddrPort, p *router.Packet) {
	metrics := l.metrics
	sc := router.ClassOfSize(len(p.RawPacket))
	metrics[sc].InputPacketsTotal.Inc()
	metrics[sc].InputBytesTotal.Add(float64(len(p.RawPacket)))
	procID, err := computeProcID(p.RawPacket, len(l.procQs), l.seed)
	if err != nil {
		log.Debug("Error while computing procID", "err", err)
		l.pool.Put(p)
		metrics[sc].DroppedPacketsInvalid.Inc()
		return
	}

	p.Link = l
	// This is an unconnected link. We must record the src address in case the packet is turned
	// around by SCMP.

	// One of p.RemoteAddr or srcAddr becomes garbage. Keeping srcAddr doesn't require copying.
	p.RemoteAddr = unsafe.Pointer(srcAddr)

	select {
	case l.procQs[procID] <- p:
	default:
		l.pool.Put(p)
		metrics[sc].DroppedPacketsBusyProcessor.Inc()
	}
}

func newInternalLink(
	localAddr *netip.AddrPort,
	conn *udpConnection,
	svc *router.Services[netip.AddrPort],
	dispatchStart, dispatchEnd, dispatchRedirect uint16,
	metrics *router.InterfaceMetrics,
) *internalLink {
	// We prepare an incomplete header; it is still faster to patch it than recreate it
	// from scratch for every packet.
	il := &internalLink{
		egressQ:          conn.queue,
		metrics:          metrics,
		svc:              svc,
		seed:             conn.seed,
		dispatchStart:    dispatchStart,
		dispatchEnd:      dispatchEnd,
		dispatchRedirect: dispatchRedirect,
	}
	il.packHeader(localAddr)
	conn.link = il
	return il
}
