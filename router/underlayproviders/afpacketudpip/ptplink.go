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
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/bfd"
)

// ptpLink is a point-to-point link. All links share a single raw socket per NIC. However
// point to point links are dedicated to a single src/dst pair.
// TODO(jiceatscion): a lot of code could be deduplicated between the two link implementations.
type ptpLink struct {
	procQs     []chan *router.Packet
	header     []byte
	localMAC   net.HardwareAddr // replace w/ 6 bytes?
	pool       router.PacketPool
	hdrMutex   sync.Mutex
	localAddr  *netip.AddrPort
	remoteAddr *netip.AddrPort
	egressQ    chan<- *router.Packet
	metrics    *router.InterfaceMetrics
	bfdSession *bfd.Session
	remoteMAC  *[6]byte
	scope      router.LinkScope
	seed       uint32
	ifID       uint16 // 0 for sibling links
	is4        bool
}

func (l *ptpLink) seekNeighbor(remoteIP netip.Addr) {
	p := l.pool.Get()
	serBuf := router.NewSerializeProxyStart(p.RawPacket, 128)
	var err error

	if l.is4 {
		ethernet := layers.Ethernet{
			SrcMAC:       l.localMAC,
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeARP,
		}
		arp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			HwAddressSize:     6,
			Protocol:          layers.EthernetTypeIPv4,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   l.localMAC,
			SourceProtAddress: l.localAddr.Addr().AsSlice(),
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
			DstProtAddress:    remoteIP.AsSlice(),
		}
		err = gopacket.SerializeLayers(&serBuf, seropts, &ethernet, &arp)
	} else {
		mcAddr := remoteIP.AsSlice()
		copy(mcAddr, ndpMcastPrefix)
		ethernet := layers.Ethernet{
			SrcMAC:       l.localMAC,
			DstMAC:       net.HardwareAddr{0x33, 0x33, 0xff, mcAddr[13], mcAddr[14], mcAddr[15]},
			EthernetType: layers.EthernetTypeIPv6,
		}
		ipv6 := layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   64,
			SrcIP:      l.localAddr.Addr().AsSlice(),
			DstIP:      mcAddr,
		}
		icmp6 := layers.ICMPv6{
			TypeCode: layers.ICMPv6TypeNeighborSolicitation,
		}
		request := layers.ICMPv6NeighborSolicitation{
			TargetAddress: remoteIP.AsSlice(),
			Options: layers.ICMPv6Options{
				layers.ICMPv6Option{Type: layers.ICMPv6OptSourceAddress, Data: l.localMAC},
			},
		}
		_ = icmp6.SetNetworkLayerForChecksum(&ipv6)
		err = gopacket.SerializeLayers(&serBuf, seropts, &ethernet, &ipv6, &icmp6, &request)
	}

	if err != nil {
		// The only possible reason for this is in the few lines above.
		panic("Cannot serialize arp packet")
	}
	p.RawPacket = serBuf.Bytes()

	log.Debug("Neighbor request sent ptp", "whohas", remoteIP, "tell", l.localAddr.Addr())

	select {
	case l.egressQ <- p:
	default:
	}
}

var pending = [6]byte{0, 0, 0, 0, 0, 0}

// Expensive. Call only to make a few prefab headers.
// This must be called with hdrMutex locked.
func (l *ptpLink) packHeader() {
	dstIP := l.remoteAddr.Addr()
	if l.remoteMAC == nil {
		// Trigger the address resolution and then wait.
		l.remoteMAC = &pending
		l.seekNeighbor(dstIP)
	}
	if l.remoteMAC == &pending {
		return
	}

	// We have the address resolved, so build the header.
	sb := gopacket.NewSerializeBuffer()
	srcIP := l.localAddr.Addr()

	if l.is4 {
		ethernet := layers.Ethernet{
			SrcMAC:       l.localMAC,
			DstMAC:       l.remoteMAC[:],
			EthernetType: layers.EthernetTypeIPv4,
		}
		udp := layers.UDP{
			SrcPort: layers.UDPPort(l.localAddr.Port()),
			DstPort: layers.UDPPort(l.remoteAddr.Port()),
		}
		ip := layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			SrcIP:    srcIP.AsSlice(),
			DstIP:    dstIP.AsSlice(),
			Protocol: layers.IPProtocolUDP,
			Flags:    layers.IPv4DontFragment, // Sure about that?
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
	ethernet := layers.Ethernet{
		SrcMAC:       l.localMAC,
		DstMAC:       l.remoteMAC[:],
		EthernetType: layers.EthernetTypeIPv6,
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(l.localAddr.Port()),
		DstPort: layers.UDPPort(l.remoteAddr.Port()),
	}

	ip := layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolUDP,
		HopLimit:   64,
		SrcIP:      srcIP.AsSlice(),
		DstIP:      dstIP.AsSlice(),
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

// addHeader fetches the then-most-current version of the canned header and pastes it on the packet.
// If no canned header is available, this method returns false and the packet is left without a
// header. Note that packHeader triggers an address resolution if a canned header cannot be
// constructed immediately.
func (l *ptpLink) addHeader(p *router.Packet) bool {
	l.hdrMutex.Lock()
	if l.header == nil {
		l.packHeader()
	}
	header := l.header
	l.hdrMutex.Unlock()
	if header == nil {
		return false
	}
	p.RawPacket = p.WithHeader(len(header))
	copy(p.RawPacket, header)
	return true
}

// TODO(jiceatscion): can do cleaner, more legible, faster?
func (l *ptpLink) finishPacket(p *router.Packet) bool {
	payloadLen := len(p.RawPacket)
	if !l.addHeader(p) {
		return false
	}
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
		return true
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
	return true
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
			log.Error("BFD session failed to start", "remote address", l.remoteAddr, "err", err)
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
	if !l.finishPacket(p) {
		// Cannot (because remote address not resolved).
		return false
	}

	select {
	case l.egressQ <- p:
	default:
		return false
	}
	return true
}

func (l *ptpLink) SendBlocking(p *router.Packet) {
	// Same as Send(). We must supply the header.
	if !l.finishPacket(p) {
		// FIXME(jiceatscion): this function could not fail. Now it can.
		return
	}

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

func (l *ptpLink) handleNeighbor(isReq bool, targetIP, senderIP netip.Addr, remoteHw [6]byte) {
	// We only care or know our one remote host. However we respond to every deserving query.
	// Per RFC826 we update opportunistically.
	l.hdrMutex.Lock()

	// This is needed to minimize GC pressure. It gets assigned to a dynamically allocated
	// copy only when there is no better choice.
	var remoteHwP *[6]byte

	if senderIP == l.remoteAddr.Addr() {
		// We want.
		if l.remoteMAC == nil || *l.remoteMAC != remoteHw {
			// An actual new address.
			l.remoteMAC = &remoteHw

			log.Debug("Neighbor cache updated ptp", "IP", senderIP, "isat", remoteHw,
				"on", l.localAddr.Addr())

			// Invalidate the packed header if needed.
			if l.remoteAddr.Addr() == senderIP {
				l.header = nil
			}
		}
		// We point at something that we're keeping anyway.
		remoteHwP = l.remoteMAC
	} else if targetIP == l.localAddr.Addr() && !senderIP.IsUnspecified() {
		// Don't want but may deserve a response
		// No choice, senderMAC escapes to the heap.
		remoteHwP = &remoteHw
	} else {
		// We don't want and no response needed.
		isReq = false
	}
	l.hdrMutex.Unlock()

	// Respond?
	// TODO(jiceatscion): since we find the interfaces by address, we assume the addresses are
	// assigned in the regular ip stack. So the kernel should be doing the responding just fine.
	// Therefore, may be responding isn't required; at least as long as we use assigned addresses.
	if !isReq {
		return
	}
	if targetIP == senderIP {
		// gratuitous request (at least in the V4 world).
		return
	}
	p := l.pool.Get()
	serBuf := router.NewSerializeProxyStart(p.RawPacket, 128)
	var err error

	if l.is4 {
		ethernet := layers.Ethernet{
			SrcMAC:       l.localMAC,
			DstMAC:       remoteHwP[:],
			EthernetType: layers.EthernetTypeARP,
		}
		arp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			HwAddressSize:     6,
			Protocol:          layers.EthernetTypeIPv4,
			ProtAddressSize:   4,
			Operation:         layers.ARPReply,
			SourceHwAddress:   l.localMAC,
			SourceProtAddress: l.localAddr.Addr().AsSlice(),
			DstHwAddress:      remoteHwP[:],
			DstProtAddress:    senderIP.AsSlice(),
		}
		err = gopacket.SerializeLayers(&serBuf, seropts, &ethernet, &arp)
	} else {
		ethernet := layers.Ethernet{
			SrcMAC:       l.localMAC,
			DstMAC:       remoteHwP[:],
			EthernetType: layers.EthernetTypeIPv6,
		}
		ipv6 := layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   64,
			SrcIP:      l.localAddr.Addr().AsSlice(),
			DstIP:      senderIP.AsSlice(),
		}
		icmp6 := layers.ICMPv6{
			TypeCode: layers.ICMPv6TypeNeighborAdvertisement,
		}
		response := layers.ICMPv6NeighborAdvertisement{
			Flags:         0x60, // Sollicited | Override.
			TargetAddress: l.localAddr.Addr().AsSlice(),
			Options: layers.ICMPv6Options{
				layers.ICMPv6Option{Type: layers.ICMPv6OptTargetAddress, Data: remoteHwP[:]},
			},
		}
		_ = icmp6.SetNetworkLayerForChecksum(&ipv6)
		err = gopacket.SerializeLayers(&serBuf, seropts, &ethernet, &ipv6, &icmp6, &response)
	}
	if err != nil {
		// The only possible reason for this is in the few lines above.
		panic(fmt.Sprintf("Cannot serialize neighbor response: %v", err))
	}
	p.RawPacket = serBuf.Bytes()

	log.Debug("Neighbor response sent ptp", "amhere", l.localAddr.Addr(), "localMAC", l.localMAC,
		"to", senderIP)

	select {
	case l.egressQ <- p:
	default:
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
		localMAC:   conn.localMAC,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		egressQ:    conn.queue,
		metrics:    metrics,
		bfdSession: bfd,
		seed:       conn.seed,
		ifID:       ifID,
		scope:      router.External,
		is4:        localAddr.Addr().Is4(),
	}
	conn.links[*remoteAddr] = l

	// Packheader also announces ourselves. As a result, there's a decent chance that both sides
	// have their mutual addresses resolved before the first real packet is sent.
	l.packHeader()

	log.Debug("Link", "scope", "external", "local", localAddr, "localMAC", conn.localMAC,
		"remote", remoteAddr)
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
		localMAC:   conn.localMAC,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		egressQ:    conn.queue,
		metrics:    metrics,
		bfdSession: bfd,
		seed:       conn.seed,
		ifID:       0,
		scope:      router.Sibling,
		is4:        localAddr.Addr().Is4(),
	}
	conn.links[*remoteAddr] = l

	// Packheader also announces ourselves. As a result, there's a decent chance that both sides
	// have their mutual addresses resolved before the first real packet is sent.
	l.packHeader()

	log.Debug("Link", "scope", "sibling", "local", localAddr, "localMAC", conn.localMAC,
		"remote", remoteAddr)
	return l
}
