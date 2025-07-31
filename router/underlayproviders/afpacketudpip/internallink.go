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
	"sync/atomic"

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
	localAddr        *netip.AddrPort
	egressQ          chan *router.Packet
	metrics          *router.InterfaceMetrics
	neighbors        *neighborCache
	svc              *router.Services[netip.AddrPort]
	backlogCheck     chan netip.Addr
	sendBacklogDone  chan struct{}
	running          atomic.Bool
	seed             uint32
	dispatchStart    uint16
	dispatchEnd      uint16
	dispatchRedirect uint16
	is4              bool
}

// getRemote returns the ip address and port of the far end of the packet's trip.
//
// It is used as follows:
// * We set it from src address when we ingest a packet: it will be used for any SCMP response.
// * We set it when the main router code has us resolve the destination (for non-responses).
// * We use it as destination when finally sending the packet.
//
// That address and port are stored at the beginning of the packet buffer so we do not need to
// allocate. getRemoteAddr returns a slice pointing directly at that storage. It is meant to
// copied into the outgoing packet header.
func getRemoteAddr(p *router.Packet, is4 bool) ([]byte, uint16) {
	if is4 {
		bh := p.BuffHead(6)
		return bh[:4], binary.BigEndian.Uint16(bh[4:6])
	}
	bh := p.BuffHead(18)
	return bh[:16], binary.BigEndian.Uint16(bh[16:18])
}

// setRemote stores the ip address and port of the far end of the packet's trip.
//
// That address and port are stored at the beginning of the packet buffer.
func setRemoteAddr(p *router.Packet, ip []byte, port uint16) {
	// FWIW: The storage format is identical to that produced by AddrPort.marshalBinary
	// as long as there's no zone. Just without all the hullabaloo because we never need a netip.
	bh := p.BuffHead(len(ip) + 2)
	copy(bh, ip)
	binary.BigEndian.PutUint16(bh[len(ip):], port)
}

// This is called during initialization only and does not need the neighbors cache. The header
// is incomplete and gets patched for each packet.
func (l *internalLink) packHeader() {
	sb := gopacket.NewSerializeBuffer()
	srcIP := l.localAddr.Addr()
	if l.is4 {
		ethernet := layers.Ethernet{
			SrcMAC:       l.localMAC,
			DstMAC:       zeroMacAddr[:],
			EthernetType: layers.EthernetTypeIPv4,
		}
		udp := layers.UDP{
			SrcPort: layers.UDPPort(l.localAddr.Port()),
		}
		ip := layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			SrcIP:    srcIP.AsSlice(),
			DstIP:    netip.IPv4Unspecified().AsSlice(),
			Protocol: layers.IPProtocolUDP,
			Flags:    layers.IPv4DontFragment, // Sure about that?
		}
		_ = udp.SetNetworkLayerForChecksum(&ip)
		err := gopacket.SerializeLayers(sb, seropts, &ethernet, &ip, &udp)
		if err != nil {
			// The only possible reason for this is in the few lines above.
			panic("cannot serialize static header")
		}

		// We have to truncate the result; gopacket is scared of generating a packet shorter than
		// the ethernet minimum.
		l.header = sb.Bytes()[:42]
		return
	}
	ethernet := layers.Ethernet{
		SrcMAC:       l.localMAC,
		DstMAC:       zeroMacAddr[:],
		EthernetType: layers.EthernetTypeIPv6,
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(l.localAddr.Port()),
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
		panic("cannot serialize static header")
	}
	// We have to truncate the result; gopacket is scared of generating a packet shorter than the
	// ethernet minimum.
	l.header = sb.Bytes()[:62]
}

// addHeader fetches the canned header, which never changes, pastes it on the packet, and patches
// in the destination. If the destination is not resolved, this method returns false and the
// packet is left with an incorrect header. Note that an address resolution is triggered if the
// destination is not already resolved.
func (l *internalLink) addHeader(p *router.Packet) bool {
	dstIPBytes, dstPort := getRemoteAddr(p, l.is4)
	dstIP, ok := netip.AddrFromSlice(dstIPBytes)
	if !ok {
		// This is an internal error: these bytes were stored and validated by us.
		panic("Broken remote address")
	}
	// Resolve the destination MAC address if we can.
	l.neighbors.Lock()
	dstMac, backlog := l.neighbors.get(dstIP) // Send ARP/NDP req as needed.
	l.neighbors.Unlock()
	if dstMac == nil {
		// We don't have an address to offer, but we have a backlog queue.
		select {
		case backlog <- p:
		default:
			sc := router.ClassOfSize(len(p.RawPacket))
			l.metrics[sc].DroppedPacketsBusyForwarder[p.TrafficType].Inc()
			l.pool.Put(p)
		}
		return false
	}

	// Prepend the canned header
	p.RawPacket = p.WithHeader(len(l.header))
	copy(p.RawPacket, l.header)

	// Inject dest.
	copy(p.RawPacket, dstMac[:])
	if l.is4 {
		copy(p.RawPacket[ipv4DstOffset:], dstIPBytes) // Can do cheaper?
		binary.BigEndian.PutUint16(p.RawPacket[udpv4DstPortOffset:], dstPort)
	} else {
		copy(p.RawPacket[ipv6DstOffset:], dstIPBytes) // Can do cheaper?
		binary.BigEndian.PutUint16(p.RawPacket[udpv6DstPortOffset:], dstPort)
	}
	return true
}

// TODO(jiceatscion): can do cleaner, more legible, faster?
func (l *internalLink) finishPacket(p *router.Packet) bool {
	payloadLen := len(p.RawPacket)
	if !l.addHeader(p) {
		return false
	}
	if l.is4 {
		// Fix the IP total length field
		binary.BigEndian.PutUint16(p.RawPacket[ipv4LenOffset:], uint16(payloadLen)+ipv4Len+udpLen)

		// Update UDP length
		binary.BigEndian.PutUint16(p.RawPacket[udpv4LenOffset:], uint16(payloadLen)+udpLen)

		// For IPv4 fix the IP checksum
		p.RawPacket[ipv4SumOffset] = 0
		p.RawPacket[ipv4SumOffset+1] = 0
		csum := gopacket.ComputeChecksum(p.RawPacket[ipOffset:udpv4Offset], 0)
		binary.BigEndian.PutUint16(p.RawPacket[ipv4SumOffset:], gopacket.FoldChecksum(csum))

		// For IPV4 we can screw the UDP checksum
		p.RawPacket[udpv4SumOffset] = 0
		p.RawPacket[udpv4SumOffset+1] = 0
		return true
	}

	// Fix the IPv6 payload length field (udp plus the scion stuff)
	binary.BigEndian.PutUint16(p.RawPacket[ipv6LenOffset:], uint16(payloadLen)+udpLen)

	// Update UDP length
	binary.BigEndian.PutUint16(p.RawPacket[udpv6LenOffset:], uint16(payloadLen)+udpLen)

	// Zero-out the checksum as it is part of the computation's input.
	p.RawPacket[udpv6SumOffset] = 0
	p.RawPacket[udpv6SumOffset+1] = 0

	// For IPV6 we must compute the UDP checksum.
	// In theory we could dispense with it as we're a tunneling protocol; however all the plain
	// udp underlay implementations would drop the packets. TODO(jiceatscion): save a few cycles
	// by using UDPlite?
	zerosAndProto := []byte{0, 0, 0, 17}
	csum := gopacket.ComputeChecksum(p.RawPacket[ipv6SrcOffset:udpv6Offset], 0)         // src+dst
	csum = gopacket.ComputeChecksum(p.RawPacket[udpv6LenOffset:udpv6LenOffset+2], csum) // length
	csum = gopacket.ComputeChecksum(zerosAndProto, csum)                                // proto num
	csum = gopacket.ComputeChecksum(p.RawPacket[udpv6Offset:], csum)                    // all
	binary.BigEndian.PutUint16(p.RawPacket[udpv6SumOffset:], gopacket.FoldChecksum(csum))
	return true
}

func (l *internalLink) start(
	ctx context.Context,
	procQs []chan *router.Packet,
	pool router.PacketPool,
) {
	wasRunning := l.running.Swap(true)
	if wasRunning {
		return
	}
	// procQs and pool are never known before all configured links have been instantiated. So we
	// get them only now. We didn't need it earlier since the connections have not been started yet.
	l.procQs = procQs
	l.pool = pool

	// cache ticker is desirable.
	l.neighbors.start(l.pool)

	// We do not have a known peer that we can resolve ahead of time, but we can at least save
	// peers that are already up from having to resolve us and may be drop the first packet.
	localIP := l.localAddr.Addr()
	l.neighbors.seekNeighbor(&localIP)

	// Backlog sender
	go func() {
		defer log.HandlePanic()
		dstAddr := netip.Addr{}
		for l.running.Load() {
			l.sendBacklog(dstAddr)
			dstAddr = <-l.backlogCheck
		}
		close(l.sendBacklogDone)
	}()
}

func (l *internalLink) stop() {
	wasRunning := l.running.Swap(false)
	if wasRunning {
		// wakeup! Time to die.
		select {
		case l.backlogCheck <- netip.Addr{}:
		default:
		}
		<-l.sendBacklogDone
	}

	l.neighbors.stop()
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
	if port < l.dispatchStart || port > l.dispatchEnd {
		port = l.dispatchRedirect
	}

	setRemoteAddr(p, dstAddr.AsSlice(), port)
	return nil
}

func (l *internalLink) sendBacklog(dstAddr netip.Addr) {
	l.neighbors.Lock()
	backlog := l.neighbors.getBacklog(dstAddr)
	l.neighbors.Unlock()

	if backlog == nil {
		return
	}
	givenup := false
	for {
		select {
		case p := <-backlog:
			if givenup {
				sc := router.ClassOfSize(len(p.RawPacket))
				l.metrics[sc].DroppedPacketsBusyForwarder[p.TrafficType].Inc()
				l.pool.Put(p)
				continue
			}
			// The neighbor cache doesn't know the dest port, but the full address is in the packet.
			if !l.finishPacket(p) {
				// Note that this packet goes back onto the backlog so we will drop it at the end of
				// the loop. TODO(jiceatscion): need new drop reason.
				givenup = true
				continue
			}
			select {
			case l.egressQ <- p:
			default:
				sc := router.ClassOfSize(len(p.RawPacket))
				l.metrics[sc].DroppedPacketsBusyForwarder[p.TrafficType].Inc()
				l.pool.Put(p)
			}
		default:
			// Backlog drained (for now).
			return
		}
	}
}

func (l *internalLink) Send(p *router.Packet) {

	// TODO(jiceatscion): The packet's destination is in the packet's meta-data; it was put there by
	// Resolve() We need to craft a header in front of the packet.  May be resolve could do that,
	// instead of just storing the destination in the packet structure. That would save us the
	// allocation of address but requires some more changes to the dataplane code structure.

	if !l.finishPacket(p) {
		// The packet got put on the backlog (or discarded if the backlog is full).
		return
	}
	select {
	case l.egressQ <- p:
	default:
		sc := router.ClassOfSize(len(p.RawPacket))
		l.metrics[sc].DroppedPacketsBusyForwarder[p.TrafficType].Inc()
		l.pool.Put(p)
	}
}

// Only tests actually use this method, but since we have to have it, we might as well implement it
// ~correctly. Doesn't hurt. TODO(jiceatscion): deal with backlog (or not).
func (l *internalLink) SendBlocking(p *router.Packet) {
	if l.finishPacket(p) {
		l.egressQ <- p
	}
	// else, backlog'd or discarded => non-blocking after all. Sorry.
}

// receive delivers an incoming packet to the appropriate processing queue.
// Because this link is not associated with a specific remote address, the src
// address of the packet is recorded in the packet structure. This may be used
// as the destination if SCMP responds.
func (l *internalLink) receive(p *router.Packet) {
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

	select {
	case l.procQs[procID] <- p:
	default:
		l.pool.Put(p)
		metrics[sc].DroppedPacketsBusyProcessor.Inc()
	}
}

// We have to deal with the idiosyncracies of both ARP and NDP, here.
// In ARP responses the address of the recipient is DstProtAddress while the address being
// resolved is SourceProtAddress. In NDP responses, the address of the recipient is in the IP header
// and the address being resolved is always TargetAddress. In ARP requests the address of the sender
// is srcProtAddress while the address being resolved dstProtAddress. In NDP requests the address
// of the sender is in the IP header, while the address being resolved is TargetAddress.
// Since this method is called for both requests and responses and for both ARP and NDP, we have
// to make our own convention:
// target is always the address being resolved.
// sender is always the sender of the packet.
// rcpt is always the intended recipient, when one is specified. It is also the target when isReq
// is true.
//
// We do use requests to populate our cache, which means that we use sender for that, instead of
// target. That way we gain knowledge from requests, even when the target is something else (for
// example, the local address).
func (l *internalLink) handleNeighbor(
	isReq bool,
	targetIP, senderIP, rcptIP netip.Addr,
	remoteHw [6]byte,
) {
	// Don't pollute our table with stuff that we can't have asked. However, per RFC826, update
	// what we already have when given a chance.
	// remoteHwP always points at an in-cache MAC address, which reduces GC pressure.
	// We respond only to peers that we keep in the cache.
	var remoteHwP *[6]byte
	changed := false

	l.neighbors.Lock()
	found := l.neighbors.check(senderIP) // pending => found.
	if (rcptIP == l.localAddr.Addr() &&
		senderIP != targetIP && // could be response or could be gratuitous. If !found, not wanted.
		!senderIP.IsUnspecified()) || found {

		// Good to cache or update
		remoteHwP, changed = l.neighbors.put(senderIP, remoteHw)
	} else {
		// Not cacheable => No response needed either.
		isReq = false
	}
	l.neighbors.Unlock()

	if changed {
		select {
		case l.backlogCheck <- senderIP:
		default:
		}
	}

	// We do respond. The kernel might or might not, depending on how we setup interfaces.
	if !isReq {
		return
	}
	if targetIP != l.localAddr.Addr() {
		// Can be a gratuitous request or simply a request for another host.
		return
	}
	p := l.pool.Get()
	localIP := l.localAddr.Addr()
	// TODO(jiceatscion): should suppress response here too for loopback devices.
	packNeighborResp(p, &localIP, l.localMAC[:], &senderIP, remoteHwP[:], l.is4)
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
		localMAC:  conn.localMAC,
		localAddr: localAddr,
		egressQ:   conn.queue,
		metrics:   metrics,
		neighbors: newNeighborCache(
			"internal",
			conn.localMAC,
			localAddr.Addr(),
			conn.queue,
		),
		svc:              svc,
		backlogCheck:     make(chan netip.Addr, 1),
		sendBacklogDone:  make(chan struct{}),
		seed:             conn.seed,
		dispatchStart:    dispatchStart,
		dispatchEnd:      dispatchEnd,
		dispatchRedirect: dispatchRedirect,
		is4:              localAddr.Addr().Is4(),
	}
	il.packHeader()
	conn.intLinks[addrPort{ip: localAddr.Addr(), port: localAddr.Port()}] = il

	log.Debug("***** Link", "scope", "internal", "local", localAddr, "localMAC", conn.localMAC)
	return il
}

func (l *internalLink) String() string {
	return fmt.Sprintf("Internal: local: %s", l.localAddr)
}
