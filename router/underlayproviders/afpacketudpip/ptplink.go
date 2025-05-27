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
	"errors"
	"net"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/bfd"
)

// ptpLink is a point-to-point link. All links share a single raw socket per NIC. However
// point to point links are dedicated to a single src/dst pair.
type ptpLink struct {
	procQs     []chan *router.Packet
	header     []byte
	name       string // For logs
	egressQ    chan<- *router.Packet
	metrics    *router.InterfaceMetrics
	pool       router.PacketPool
	bfdSession *bfd.Session
	scope      router.LinkScope
	seed       uint32
	ifID       uint16 // 0 for sibling links
	is4        bool
}

// Expensive. Call only to make a few prefab headers.
func (l *ptpLink) packHeader(src, dst *netip.AddrPort) {

	sb := gopacket.NewSerializeBuffer()
	ethernet := layers.Ethernet{
		// FIXME! We must get those from the interface and from ARP!
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x1, 0x1},
		DstMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x2, 0x2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(src.Port()),
		DstPort: layers.UDPPort(dst.Port()),
	}

	l.is4 = src.Addr().Is4()

	if l.is4 {

		ip := layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			SrcIP:    src.Addr().AsSlice(),
			DstIP:    dst.Addr().AsSlice(),
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
		DstIP:      dst.Addr().AsSlice(),
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
func (l *ptpLink) addHeader(p *router.Packet) {
	payloadLen := len(p.RawPacket)
	p.RawPacket = p.WithHeader(len(l.header))
	copy(p.RawPacket, l.header)

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

func (l *ptpLink) start(
	ctx context.Context,
	procQs []chan *router.Packet,
	pool router.PacketPool,
) {
	// procQs and pool are never known before all configured links have been instantiated.  So we
	// get them only now. We didn't need it earlier since the connections have not been started yet.
	l.procQs = procQs
	l.pool = pool
	if l.bfdSession == nil {
		return
	}
	go func() {
		defer log.HandlePanic()
		if err := l.bfdSession.Run(ctx); err != nil && !errors.Is(err, bfd.ErrAlreadyRunning) {
			log.Error("BFD session failed to start", "remote address", l.name, "err", err)
		}
	}()
}

func (l *ptpLink) stop() {
	if l.bfdSession == nil {
		return
	}
	l.bfdSession.Close()
}

func (l *ptpLink) IfID() uint16 {
	return l.ifID
}

func (l *ptpLink) Metrics() *router.InterfaceMetrics {
	return l.metrics
}

func (l *ptpLink) Scope() router.LinkScope {
	return l.scope
}

func (l *ptpLink) BFDSession() *bfd.Session {
	return l.bfdSession
}

func (l *ptpLink) IsUp() bool {
	return l.bfdSession == nil || l.bfdSession.IsUp()
}

// Resolve should not be useful on a sibling or external link so we don't implement it yet.
func (l *ptpLink) Resolve(p *router.Packet, host addr.Host, port uint16) error {
	return errResolveOnNonInternalLink
}

func (l *ptpLink) Send(p *router.Packet) bool {
	// We do not have an underlying connection. Instead we supply the entire underlay header. We
	// have it mostly canned and paste it in front of the packet.
	l.addHeader(p)

	select {
	case l.egressQ <- p:
	default:
		return false
	}
	return true
}

func (l *ptpLink) SendBlocking(p *router.Packet) {
	// Same as Send(). We must supply the header.
	l.addHeader(p)

	l.egressQ <- p
}

// receive delivers an incoming packet to the appropriate processing queue.
func (l *ptpLink) receive(srcAddr *netip.AddrPort, p *router.Packet) {
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
	// The src address does not need to be recorded in the packet. The link has all the relevant
	// information.
	select {
	case l.procQs[procID] <- p:
	default:
		l.pool.Put(p)
		metrics[sc].DroppedPacketsBusyProcessor.Inc()
	}
}

func newPtpLinkExternal(
	localAddr *netip.AddrPort,
	remoteAddr *netip.AddrPort,
	conn *udpConnection,
	bfd *bfd.Session,
	ifID uint16,
	metrics *router.InterfaceMetrics,
) *ptpLink {
	l := &ptpLink{
		name:       remoteAddr.String(),
		egressQ:    conn.queue,
		metrics:    metrics,
		bfdSession: bfd,
		seed:       conn.seed,
		ifID:       ifID,
		scope:      router.External,
	}
	l.packHeader(localAddr, remoteAddr)
	conn.links[*remoteAddr] = l
	return l
}

func newPtpLinkSibling(
	localAddr *netip.AddrPort,
	remoteAddr *netip.AddrPort,
	conn *udpConnection,
	bfd *bfd.Session,
	metrics *router.InterfaceMetrics,
) *ptpLink {
	l := &ptpLink{
		name:       remoteAddr.String(),
		egressQ:    conn.queue,
		metrics:    metrics,
		bfdSession: bfd,
		seed:       conn.seed,
		ifID:       0,
		scope:      router.Sibling,
	}
	l.packHeader(localAddr, remoteAddr)
	conn.links[*remoteAddr] = l
	return l
}
