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
	"sync"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/bfd"
)

// internalLink is actually a half link. It is not associated with a specific remote address.
// TODO(jiceatscion): a lot of code could be deduplicated between the two link implementations.
type internalLink struct {
	procQs           []chan *router.Packet
	header           []byte
	localMAC         net.HardwareAddr // replace w/ 6 bytes?
	pool             router.PacketPool
	hdrMutex         sync.Mutex
	localAddr        *netip.AddrPort
	egressQ          chan *router.Packet
	metrics          *router.InterfaceMetrics
	arpCache         map[netip.Addr]*[6]byte
	svc              *router.Services[netip.AddrPort]
	seed             uint32
	dispatchStart    uint16
	dispatchEnd      uint16
	dispatchRedirect uint16
	is4              bool
}

func (l *internalLink) seekNeighbor(remoteIP netip.Addr) {
	if !l.is4 {
		// NDP  Not implemented yet
		return
	}

	// TODO(jiceatscion): use a canned arp packet?
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
	log.Debug("ARP Request sent internal", "whohas", remoteIP, "tell", l.localAddr.Addr())
	p := l.pool.Get()
	serBuf := router.NewSerializeProxyStart(p.RawPacket, 60)
	err := gopacket.SerializeLayers(&serBuf, seropts, &ethernet, &arp)
	if err != nil {
		// The only possible reason for this is in the few lines above.
		panic("Cannot serialize arp packet")
	}
	p.RawPacket = serBuf.Bytes()
	select {
	case l.egressQ <- p:
	default:
	}
}

// Expensive. Call only to make a few prefab headers.
// This is called during initialization  only. No need for the mutex.
// However, addHeader needs to consult/update the arp cache for each packet; that's when the
// mutex is needed.
// We prepare an incomplete header; it is still faster to patch it than recreate it
// from scratch for every packet.
func (l *internalLink) packHeader() {

	sb := gopacket.NewSerializeBuffer()
	srcIP := l.localAddr.Addr()

	ethernet := layers.Ethernet{
		SrcMAC:       l.localMAC,
		DstMAC:       []byte{0, 0, 0, 0, 0, 0},
		EthernetType: layers.EthernetTypeIPv4,
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(l.localAddr.Port()),
	}
	if l.is4 {
		ip := layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			SrcIP:    srcIP.AsSlice(),
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
		SrcIP:      srcIP.AsSlice(),
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

// TODO(jiceatscion): can do cleaner, more legible, faster?
// This runs asynchronously with updating the arp table. Hence locking hdrMutex.
func (l *internalLink) addHeader(p *router.Packet, dst *netip.AddrPort) bool {
	payloadLen := len(p.RawPacket)
	dstIP := dst.Addr()

	// Resolve the destination MAC address if we can.
	l.hdrMutex.Lock()
	dstMac, found := l.arpCache[dstIP]
	if dstMac == nil { // pending or missing
		if !found {
			// Trigger the address resolution.
			l.arpCache[dstIP] = nil // Mark pending
			l.hdrMutex.Unlock()
			l.seekNeighbor(dstIP)
		} else {
			l.hdrMutex.Unlock()
		}
		// Either way, not ready yet.
		return false
	}

	// Prepend the canned header
	p.RawPacket = p.WithHeader(len(l.header))
	copy(p.RawPacket, l.header)
	l.hdrMutex.Unlock()

	// Inject dest.
	copy(p.RawPacket, dstMac[:])
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
	if !l.addHeader(p, (*netip.AddrPort)(p.RemoteAddr)) {
		// Cannot yet resolve that address.
		return false
	}
	select {
	case l.egressQ <- p:
	default:
		return false
	}
	return true
}

func (l *internalLink) SendBlocking(p *router.Packet) {
	// Likewise: p.remoteAddress -> header.
	if !l.addHeader(p, (*netip.AddrPort)(p.RemoteAddr)) {
		// FIXME(jiceatscion): this function could not fail. Now it can.
		l.egressQ <- p
	}
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

func (l *internalLink) handleNeighbor(
	isReq bool,
	targetIP, senderIP netip.Addr,
	targetMAC, senderMAC [6]byte,
) {
	// Don't pollute our table with stuff that we can't have asked. However, per RFC826, update
	// what we already have when given a chance.
	// We avoid replacing cache entries with identical values to limit GC pressure.
	// We respond only to peers that we keep in the cache.
	l.hdrMutex.Lock()
	currentSenderMAC, have := l.arpCache[senderIP]
	if (targetIP == l.localAddr.Addr() && !senderIP.IsUnspecified()) || have {
		// Good to cache or update
		if currentSenderMAC == nil || *currentSenderMAC != senderMAC {
			// An actual new address.
			currentSenderMAC = &senderMAC
			l.arpCache[senderIP] = currentSenderMAC
			log.Debug("ARP updated cache ptp", "IP", senderIP, "isat", senderMAC,
				"on", l.localAddr.Addr())
		}
	} else {
		// Not good to cache. No response either.
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
	if !l.is4 {
		// NDP  Not implemented yet
		log.Debug("V6 cannot repond", "IP", senderIP, "isat", senderMAC, "on", l.localAddr.Addr())
		return
	}

	if targetIP == senderIP {
		// gratuitous request (at least in the V4 world).
		return
	}
	// TODO(jiceatscion): is it worth checking that the sender MAC is valid too?

	// TODO(jiceatscion): use a canned arp packet?
	ethernet := layers.Ethernet{
		SrcMAC:       l.localMAC,
		DstMAC:       currentSenderMAC[:],
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
		DstHwAddress:      currentSenderMAC[:],
		DstProtAddress:    senderIP.AsSlice(),
	}
	log.Debug("ARP Response sent internal", "amhere", l.localAddr.Addr(), "localMAC", l.localMAC,
		"to", senderIP)
	p := l.pool.Get()
	serBuf := router.NewSerializeProxyStart(p.RawPacket, 60)
	err := gopacket.SerializeLayers(&serBuf, seropts, &ethernet, &arp)
	if err != nil {
		// The only possible reason for this is in the few lines above.
		panic("Cannot serialize arp packet")
	}
	p.RawPacket = serBuf.Bytes()
	select {
	case l.egressQ <- p:
	default:
	}
}

func newInternalLink(
	localAddr *netip.AddrPort,
	conn *udpConnection,
	svc *router.Services[netip.AddrPort],
	dispatchStart, dispatchEnd, dispatchRedirect uint16,
	metrics *router.InterfaceMetrics,
) *internalLink {
	il := &internalLink{
		localMAC:         conn.localMAC,
		localAddr:        localAddr,
		egressQ:          conn.queue,
		metrics:          metrics,
		arpCache:         make(map[netip.Addr]*[6]byte),
		svc:              svc,
		seed:             conn.seed,
		dispatchStart:    dispatchStart,
		dispatchEnd:      dispatchEnd,
		dispatchRedirect: dispatchRedirect,
		is4:              localAddr.Addr().Is4(),
	}
	il.packHeader()
	conn.link = il
	log.Debug("Link", "local", localAddr, "localMAC", conn.localMAC)
	return il
}
