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
	"sync/atomic"

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
	procQs          []chan *router.Packet
	header          []byte
	localMAC        net.HardwareAddr // replace w/ 6 bytes?
	pool            router.PacketPool
	localAddr       *netip.AddrPort
	remoteAddr      *netip.AddrPort
	egressQ         chan<- *router.Packet
	metrics         *router.InterfaceMetrics
	bfdSession      *bfd.Session
	neighbors       *neighborCache
	backlogCheck    chan struct{}
	sendBacklogDone chan struct{}
	running         atomic.Bool
	scope           router.LinkScope
	seed            uint32
	ifID            uint16 // 0 for sibling links
	is4             bool
}

// Expensive. Call only to make a few prefab headers.
// This must be called with the neighbors cache locked.
// This function either sets a header, or returns a backlog queue.
func (l *ptpLink) packHeader() chan *router.Packet {
	dstIP := l.remoteAddr.Addr()

	// Resolve the destination MAC address if we can.
	dstMac, backlog := l.neighbors.get(dstIP) // Sends ARP/NDP req as needed.
	if dstMac == nil {
		// We don't have an address to offer, but we have a backlog queue.
		return backlog
	}

	// Build the header.
	sb := gopacket.NewSerializeBuffer()
	srcIP := l.localAddr.Addr()
	if l.is4 {
		ethernet := layers.Ethernet{
			SrcMAC:       l.localMAC,
			DstMAC:       dstMac[:],
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
			panic("cannot serialize static header")
		}

		// We have to truncate the result; gopacket is scared of generating a packet shorter than
		// the ethernet minimum.
		l.header = sb.Bytes()[:42]
		return nil
	}
	ethernet := layers.Ethernet{
		SrcMAC:       l.localMAC,
		DstMAC:       dstMac[:],
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
		panic("cannot serialize static header")
	}
	// We have to truncate the result; gopacket is scared of generating a packet shorter than the
	// ethernet minimum.
	l.header = sb.Bytes()[:62]
	return nil
}

// addHeader fetches the then-most-current version of the canned header and pastes it on the packet.
// If no canned header is available, this method returns false and the packet is left without a
// header. Note that packHeader triggers an address resolution if a canned header cannot be
// constructed immediately.
func (l *ptpLink) addHeader(p *router.Packet) bool {
	l.neighbors.Lock()
	var backlog chan *router.Packet
	if l.header == nil {
		backlog = l.packHeader()
	}
	header := l.header
	if header == nil {
		if backlog != nil {
			select {
			case backlog <- p:
			default:
				sc := router.ClassOfSize(len(p.RawPacket))
				l.metrics[sc].DroppedPacketsBusyForwarder[p.TrafficType].Inc()
				l.pool.Put(p)
			}
		}
	}
	l.neighbors.Unlock()

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

	// Zero-out the checksum as it is part of the computation's input.
	p.RawPacket[14+40+6] = 0
	p.RawPacket[14+40+7] = 0

	// For IPV6 we must compute the UDP checksum.
	// In theory we could dispense with it as we're a tunneling protocol; however all the plain
	// udp underlay implementations would drop the packets.
	zerosAndProto := []byte{0, 0, 0, 17}
	csum := gopacket.ComputeChecksum(p.RawPacket[14+8:14+40], 0)        // src+dst
	csum = gopacket.ComputeChecksum(p.RawPacket[14+40+4:14+40+6], csum) // UDP length
	csum = gopacket.ComputeChecksum(zerosAndProto, csum)                // 3 0s plus UDP proto num
	csum = gopacket.ComputeChecksum(p.RawPacket[14+40:], csum)          // UDP hdr and payload
	binary.BigEndian.PutUint16(p.RawPacket[14+40+6:], gopacket.FoldChecksum(csum))
	return true
}

func (l *ptpLink) start(
	ctx context.Context,
	procQs []chan *router.Packet,
	pool router.PacketPool,
) {
	wasRunning := l.running.Swap(true)
	if wasRunning {
		return
	}
	// procQs and pool are never known before all configured links have been instantiated.  So we
	// get them only now. We didn't need it earlier since the connections have not been started yet.
	l.procQs = procQs
	l.pool = pool

	// cache ticker is desirable.
	l.neighbors.start(l.pool)

	// Backlog sender
	go func() {
		defer log.HandlePanic()
		for l.running.Load() {
			l.sendBacklog()
			<-l.backlogCheck
		}
		close(l.sendBacklogDone)
	}()

	// Since we have only one peer, try and resolve it in case it's up. That's like an
	// announcement, but we can also get a response.
	peerIP := l.remoteAddr.Addr()
	l.neighbors.seekNeighbor(&peerIP)

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
	wasRunning := l.running.Swap(false)
	if wasRunning {
		select {
		case l.backlogCheck <- struct{}{}:
		default:
		}
		<-l.sendBacklogDone
	}
	l.neighbors.stop()
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
	log.Debug("Trying to resolve inbound address on non-internal link")
	return errResolveOnNonInternalLink
}

func (l *ptpLink) sendBacklog() {
	dstAddr := l.remoteAddr.Addr()
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

func (l *ptpLink) Send(p *router.Packet) {

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
func (l *ptpLink) SendBlocking(p *router.Packet) {
	if l.finishPacket(p) {
		l.egressQ <- p
	}
	// else, backlog'd or discarded => non-blocking after all. Sorry.
}

// receive delivers an incoming packet to the appropriate processing queue.
func (l *ptpLink) receive(_ *netip.AddrPort, p *router.Packet) {
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

func (l *ptpLink) handleNeighbor(
	isReq bool,
	targetIP, senderIP, _rcptIP netip.Addr,
	remoteHw [6]byte,
) {
	// We only care or know our one remote host. However we respond to every deserving query.

	// This is needed to minimize GC pressure. It gets assigned to a dynamically allocated
	// copy only when there is no better choice.
	var remoteHwP *[6]byte
	changed := false

	if senderIP == l.remoteAddr.Addr() {
		l.neighbors.Lock()
		// We want, regardless of cache content.
		remoteHwP, changed = l.neighbors.put(senderIP, remoteHw)
		if changed {
			// Time to rebuild the packed header.
			l.header = nil
		}
		l.neighbors.Unlock()
		// backlog is an unbuffered channel. Cannot post to it while holding the mutex.
		if changed {
			select {
			case l.backlogCheck <- struct{}{}:
			default:
			}
		}
	} else if targetIP == l.localAddr.Addr() && !senderIP.IsUnspecified() {
		// We don't want but it may deserve a response.
		// No choice, senderMAC escapes to the heap.
		remoteHwP = &remoteHw
	} else {
		// We don't want and no response needed.
		isReq = false
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
		neighbors: newNeighborCache(
			"sibTo_"+remoteAddr.String(),
			conn.localMAC,
			localAddr.Addr(),
			conn.queue,
		),
		bfdSession:      bfd,
		backlogCheck:    make(chan struct{}, 1),
		sendBacklogDone: make(chan struct{}),
		scope:           router.External,
		seed:            conn.seed,
		ifID:            ifID,
		is4:             localAddr.Addr().Is4(),
	}
	locMap := conn.ptpLinks[addrKey{ip: remoteAddr.Addr(), port: remoteAddr.Port()}]
	if locMap == nil {
		locMap = make(map[addrKey]udpLink)
		conn.ptpLinks[addrKey{ip: remoteAddr.Addr(), port: remoteAddr.Port()}] = locMap
	}

	locMap[addrKey{ip: localAddr.Addr(), port: localAddr.Port()}] = l
	log.Debug("***** Link", "scope", "external", "local", localAddr, "localMAC", conn.localMAC,
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
		neighbors: newNeighborCache(
			"extTo_"+remoteAddr.String(),
			conn.localMAC,
			localAddr.Addr(),
			conn.queue,
		),
		bfdSession:      bfd,
		backlogCheck:    make(chan struct{}),
		sendBacklogDone: make(chan struct{}),
		scope:           router.Sibling,
		seed:            conn.seed,
		ifID:            0,
		is4:             localAddr.Addr().Is4(),
	}
	locMap := conn.ptpLinks[addrKey{ip: remoteAddr.Addr(), port: remoteAddr.Port()}]
	if locMap == nil {
		locMap = make(map[addrKey]udpLink)
		conn.ptpLinks[addrKey{ip: remoteAddr.Addr(), port: remoteAddr.Port()}] = locMap
	}

	locMap[addrKey{ip: localAddr.Addr(), port: localAddr.Port()}] = l
	log.Debug("***** Link", "scope", "sibling", "local", localAddr, "localMAC", conn.localMAC,
		"remote", remoteAddr)
	return l
}

func (l *ptpLink) String() string {
	scope := "External"
	if l.scope == router.Sibling {
		scope = "Sibling"
	}
	return fmt.Sprintf("%s: local: %s remote: %s", scope, l.localAddr, l.remoteAddr)
}
