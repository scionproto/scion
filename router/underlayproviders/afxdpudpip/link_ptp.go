// Copyright 2026 SCION Association
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package afxdpudpip

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/bfd"
)

// linkPTP is a point-to-point link using AF_XDP for packet I/O.
// Multiple AF_XDP sockets (one per NIC queue) are used for parallel TX/RX.
// TX packets are routed to sockets via a flow hash to prevent reordering.
type linkPTP struct {
	procQs          []chan *router.Packet
	pool            router.PacketPool
	localAddr       *netip.AddrPort
	remoteAddr      *netip.AddrPort
	conns           []*udpConnection
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

	// Cached header template. Built once when the remote MAC is resolved,
	// then patched per-packet for length and checksum fields.
	header atomic.Pointer[[]byte]
}

// buildHeader constructs the Ethernet+IP+UDP header template.
// Must be called with the neighbor cache locked.
func (l *linkPTP) buildHeader() chan *router.Packet {
	dstIP := l.remoteAddr.Addr()

	dstMac, backlog := l.neighbors.get(dstIP)
	if dstMac == nil {
		return backlog
	}

	srcIP := l.localAddr.Addr()
	srcPort := l.localAddr.Port()
	dstPort := l.remoteAddr.Port()

	var hdr []byte
	if l.is4 {
		hdr = make([]byte, ethLen+ipv4Len+udpLen)

		// Ethernet header
		copy(hdr[0:6], dstMac[:])
		copy(hdr[6:12], l.conns[0].localMAC)
		binary.BigEndian.PutUint16(hdr[12:14], 0x0800) // IPv4

		// IPv4 header template (lengths/checksum patched per-packet)
		src4 := srcIP.As4()
		dst4 := dstIP.As4()
		buildIPv4Header(hdr[ethLen:], src4, dst4, 0)

		// UDP header template (length patched per-packet)
		buildUDPHeader(hdr[ethLen+ipv4Len:], srcPort, dstPort, 0)

	} else {
		hdr = make([]byte, ethLen+ipv6Len+udpLen)

		// Ethernet header
		copy(hdr[0:6], dstMac[:])
		copy(hdr[6:12], l.conns[0].localMAC)
		binary.BigEndian.PutUint16(hdr[12:14], 0x86DD) // IPv6

		// IPv6 header template
		src6 := srcIP.As16()
		dst6 := dstIP.As16()
		buildIPv6Header(hdr[ethLen:], src6, dst6, 0)

		// UDP header template
		buildUDPHeader(hdr[ethLen+ipv6Len:], srcPort, dstPort, 0)
	}

	l.header.Store(&hdr)
	return nil
}

// finishPacket prepends headers to the packet and fixes up length/checksum fields.
// On success (true), the packet is ready to send and the caller owns it.
// On failure (false), the packet has already been disposed of (backlogged or
// returned to pool); the caller must not touch it.
func (l *linkPTP) finishPacket(p *router.Packet) bool {
	hdrp := l.header.Load()
	if hdrp == nil {
		// Try to build header
		l.neighbors.lock.Lock()
		backlog := l.buildHeader()
		hdrp = l.header.Load()
		l.neighbors.lock.Unlock()

		if hdrp == nil {
			if backlog != nil {
				select {
				case backlog <- p:
				default:
					sc := router.ClassOfSize(len(p.RawPacket))
					l.metrics[sc].DroppedPacketsBusyForwarder[p.TrafficType].Inc()
					l.pool.Put(p)
				}
			}
			return false
		}
	}

	hdr := *hdrp
	payloadLen := len(p.RawPacket)

	// Prepend the header template
	p.RawPacket = p.WithHeader(len(hdr))
	copy(p.RawPacket, hdr)

	if l.is4 {
		// Fix IPv4 total length
		ipTotalLen := ipv4Len + udpLen + payloadLen
		binary.BigEndian.PutUint16(p.RawPacket[ethLen+2:], uint16(ipTotalLen))

		// Fix UDP length
		binary.BigEndian.PutUint16(
			p.RawPacket[ethLen+ipv4Len+4:],
			uint16(udpLen+payloadLen),
		)

		// Recompute IPv4 header checksum
		p.RawPacket[ethLen+10] = 0
		p.RawPacket[ethLen+11] = 0
		csum := ipv4Checksum(p.RawPacket[ethLen : ethLen+ipv4Len])
		binary.BigEndian.PutUint16(p.RawPacket[ethLen+10:], csum)

		// IPv4 UDP checksum is optional, leave as 0
		p.RawPacket[ethLen+ipv4Len+6] = 0
		p.RawPacket[ethLen+ipv4Len+7] = 0
	} else {
		// Fix IPv6 payload length
		binary.BigEndian.PutUint16(p.RawPacket[ethLen+4:], uint16(udpLen+payloadLen))

		// Fix UDP length
		udpOff := ethLen + ipv6Len
		binary.BigEndian.PutUint16(p.RawPacket[udpOff+4:], uint16(udpLen+payloadLen))

		// Zero UDP checksum for computation
		p.RawPacket[udpOff+6] = 0
		p.RawPacket[udpOff+7] = 0

		// Compute IPv6 UDP checksum (mandatory)
		srcIP := l.localAddr.Addr().As16()
		dstIP := l.remoteAddr.Addr().As16()
		csum := udp6Checksum(srcIP, dstIP,
			p.RawPacket[udpOff:udpOff+udpLen],
			p.RawPacket[udpOff+udpLen:])
		binary.BigEndian.PutUint16(p.RawPacket[udpOff+6:], csum)
	}
	return true
}

func (l *linkPTP) start(
	ctx context.Context,
	procQs []chan *router.Packet,
	pool router.PacketPool,
) {
	wasRunning := l.running.Swap(true)
	if wasRunning {
		return
	}

	l.procQs = procQs
	l.pool = pool

	// Start neighbor cache ticker
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

	// Try to resolve peer MAC address
	peerIP := l.remoteAddr.Addr()
	l.neighbors.seekNeighbor(&peerIP)

	if l.bfdSession == nil {
		return
	}
	go func() {
		defer log.HandlePanic()
		if err := l.bfdSession.Run(ctx); err != nil &&
			!errors.Is(err, bfd.ErrAlreadyRunning) {
			log.Error("BFD session failed to start",
				"remote address", l.remoteAddr,
				"err", err)
		}
	}()
}

func (l *linkPTP) stop() {
	if l.bfdSession != nil {
		l.bfdSession.Close()
	}
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

func (l *linkPTP) IfID() uint16 {
	return l.ifID
}

func (l *linkPTP) Metrics() *router.InterfaceMetrics {
	return l.metrics
}

func (l *linkPTP) Scope() router.LinkScope {
	return l.scope
}

func (l *linkPTP) BFDSession() *bfd.Session {
	return l.bfdSession
}

func (l *linkPTP) IsUp() bool {
	return l.bfdSession == nil || l.bfdSession.IsUp()
}

func (l *linkPTP) Resolve(p *router.Packet, host addr.Host, port uint16) error {
	log.Debug("Trying to resolve inbound address on non-internal link")
	return errResolveOnNonInternalLink
}

func (l *linkPTP) sendBacklog() {
	dstAddr := l.remoteAddr.Addr()
	l.neighbors.lock.Lock()
	backlog := l.neighbors.getBacklog(dstAddr)
	l.neighbors.lock.Unlock()

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
			// Compute connection index BEFORE finishPacket prepends headers.
			connIdx := computeConnIdx(p.RawPacket, len(l.conns), l.seed)
			if !l.finishPacket(p) {
				givenup = true
				continue
			}
			select {
			case l.conns[connIdx].queue <- p:
			default:
				sc := router.ClassOfSize(len(p.RawPacket))
				l.metrics[sc].DroppedPacketsBusyForwarder[p.TrafficType].Inc()
				l.pool.Put(p)
			}
		default:
			return
		}
	}
}

func (l *linkPTP) Send(p *router.Packet) bool {
	// Compute connection index from SCION payload BEFORE finishPacket prepends headers.
	connIdx := computeConnIdx(p.RawPacket, len(l.conns), l.seed)
	if !l.finishPacket(p) {
		return false
	}
	select {
	case l.conns[connIdx].queue <- p:
	default:
		sc := router.ClassOfSize(len(p.RawPacket))
		l.metrics[sc].DroppedPacketsBusyForwarder[p.TrafficType].Inc()
		l.pool.Put(p)
		return false
	}
	return true
}

func (l *linkPTP) SendBlocking(p *router.Packet) {
	// Compute connection index from SCION payload BEFORE finishPacket prepends headers.
	connIdx := computeConnIdx(p.RawPacket, len(l.conns), l.seed)
	if l.finishPacket(p) {
		l.conns[connIdx].queue <- p
	}
}

func (l *linkPTP) receive(p *router.Packet) {
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

func newPtpLinkExternal(
	localAddr *netip.AddrPort,
	remoteAddr *netip.AddrPort,
	conns []*udpConnection,
	bfd *bfd.Session,
	ifID uint16,
	metrics *router.InterfaceMetrics,
) *linkPTP {
	l := &linkPTP{
		localAddr:       localAddr,
		remoteAddr:      remoteAddr,
		conns:           conns,
		metrics:         metrics,
		bfdSession:      bfd,
		backlogCheck:    make(chan struct{}, 1),
		sendBacklogDone: make(chan struct{}),
		scope:           router.External,
		seed:            conns[0].seed,
		ifID:            ifID,
		is4:             localAddr.Addr().Is4(),
	}
	l.neighbors = newNeighborCache(
		"extTo_"+remoteAddr.String(),
		conns[0].localMAC,
		localAddr.Addr(),
		conns[0].ifIndex,
		func(netip.Addr) {
			l.header.Store(nil)
			select {
			case l.backlogCheck <- struct{}{}:
			default:
			}
		},
	)

	// Register this link in ALL connections so any RX queue can dispatch to it.
	ft := fourTuple{
		src: addrPort{ip: remoteAddr.Addr(), port: remoteAddr.Port()},
		dst: addrPort{ip: localAddr.Addr(), port: localAddr.Port()},
	}
	for _, c := range conns {
		c.ptpLinks[ft] = l
	}

	log.Debug("***** AF_XDP Link", "scope", "external", "local", localAddr,
		"localMAC", conns[0].localMAC, "remote", remoteAddr,
		"queues", len(conns))
	return l
}

func newPtpLinkSibling(
	localAddr *netip.AddrPort,
	remoteAddr *netip.AddrPort,
	conns []*udpConnection,
	bfd *bfd.Session,
	metrics *router.InterfaceMetrics,
) *linkPTP {
	l := &linkPTP{
		localAddr:       localAddr,
		remoteAddr:      remoteAddr,
		conns:           conns,
		metrics:         metrics,
		bfdSession:      bfd,
		backlogCheck:    make(chan struct{}, 1),
		sendBacklogDone: make(chan struct{}),
		scope:           router.Sibling,
		seed:            conns[0].seed,
		ifID:            0,
		is4:             localAddr.Addr().Is4(),
	}
	l.neighbors = newNeighborCache(
		"sibTo_"+remoteAddr.String(),
		conns[0].localMAC,
		localAddr.Addr(),
		conns[0].ifIndex,
		func(netip.Addr) {
			l.header.Store(nil)
			select {
			case l.backlogCheck <- struct{}{}:
			default:
			}
		},
	)

	// Register this link in ALL connections so any RX queue can dispatch to it.
	ft := fourTuple{
		src: addrPort{ip: remoteAddr.Addr(), port: remoteAddr.Port()},
		dst: addrPort{ip: localAddr.Addr(), port: localAddr.Port()},
	}
	for _, c := range conns {
		c.ptpLinks[ft] = l
	}

	log.Debug("***** AF_XDP Link", "scope", "sibling", "local", localAddr,
		"localMAC", conns[0].localMAC, "remote", remoteAddr,
		"queues", len(conns))
	return l
}

func (l *linkPTP) String() string {
	scope := "External"
	if l.scope == router.Sibling {
		scope = "Sibling"
	}
	return fmt.Sprintf("%s: local: %s remote: %s queues: %d",
		scope, l.localAddr, l.remoteAddr, len(l.conns))
}
