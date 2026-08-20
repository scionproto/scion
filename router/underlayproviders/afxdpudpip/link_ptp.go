// Copyright 2026 SCION Association
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

//go:build linux && (amd64 || arm64)

package afxdpudpip

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/bfd"
	"github.com/scionproto/scion/router/underlayproviders/afxdpudpip/internal/checksum"
	"github.com/scionproto/scion/router/underlayproviders/afxdpudpip/internal/headers"
)

// linkPTP is a point-to-point link using AF_XDP for packet I/O.
// Multiple AF_XDP sockets (one per NIC queue) are used for parallel TX/RX.
// TX packets are routed to sockets via a flow hash to prevent reordering.
type linkPTP struct {
	procQs          []chan *router.Packet
	pool            router.PacketPool
	localAddr       *netip.AddrPort
	remoteAddr      *netip.AddrPort
	rxConns         []*udpConnection
	txConns         []*udpConnection
	metrics         *router.InterfaceMetrics
	bfdSession      *bfd.Session
	neighbors       *neighborCache
	neighborUpdated chan struct{}
	stopped         chan struct{}
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
// It does nothing while the peer MAC is unresolved, which leaves [linkPTP.header] nil.
// Must be called with the neighbor cache locked.
//
// It reports whether the caller must send what is queued for the peer once it has
// released the lock. See [neighborCache.get].
func (l *linkPTP) buildHeader() bool {
	dstIP := l.remoteAddr.Addr()

	dstMac, known, flush := l.neighbors.get(dstIP)
	if !known {
		return false
	}

	srcIP := l.localAddr.Addr()
	srcPort := l.localAddr.Port()
	dstPort := l.remoteAddr.Port()

	var hdr []byte
	if l.is4 {
		hdr = make([]byte, headers.LenEth+headers.LenIPv4+headers.LenUDP)

		// Ethernet header
		copy(hdr[0:6], dstMac[:])
		copy(hdr[6:12], l.txConns[0].localMAC)
		binary.BigEndian.PutUint16(hdr[12:14], headers.EtherTypeIPv4)

		// IPv4 header template (lengths/checksum patched per-packet)
		src4 := srcIP.As4()
		dst4 := dstIP.As4()
		headers.BuildIPv4(hdr[headers.LenEth:], src4, dst4, 0)

		// UDP header template (length patched per-packet)
		headers.BuildUDP(hdr[headers.LenEth+headers.LenIPv4:], srcPort, dstPort, 0)

	} else {
		hdr = make([]byte, headers.LenEth+headers.LenIPv6+headers.LenUDP)

		// Ethernet header
		copy(hdr[0:6], dstMac[:])
		copy(hdr[6:12], l.txConns[0].localMAC)
		binary.BigEndian.PutUint16(hdr[12:14], headers.EtherTypeIPv6)

		// IPv6 header template
		src6 := srcIP.As16()
		dst6 := dstIP.As16()
		headers.BuildIPv6(hdr[headers.LenEth:], src6, dst6, 0)

		// UDP header template
		headers.BuildUDP(hdr[headers.LenEth+headers.LenIPv6:], srcPort, dstPort, 0)
	}

	l.header.Store(&hdr)
	return flush
}

// finishPacket prepends headers to the packet and fixes up length/checksum fields.
// On success (true), the packet is ready to send and the caller owns it.
// On failure (false), the packet has already been returned to the pool;
// the caller must not touch it.
func (l *linkPTP) finishPacket(p *router.Packet, csumOffload bool) bool {
	hdrp := l.header.Load()
	if hdrp == nil {
		// The peer MAC is not resolved yet. [linkPTP.buildHeader] probes on a
		// miss and the packet waits in the peer's queue.
		peerIP := l.remoteAddr.Addr()
		l.neighbors.lock.Lock()
		flush := l.buildHeader()
		hdrp = l.header.Load()
		held := false
		var evicted *router.Packet
		if hdrp == nil {
			evicted, held = l.neighbors.hold(peerIP, p)
		}
		l.neighbors.lock.Unlock()

		if evicted != nil {
			l.dropPackets([]*router.Packet{evicted})
		}

		if flush {
			l.sendQueued()
		}
		if hdrp == nil {
			if !held {
				sc := router.ClassOfSize(len(p.RawPacket))
				l.metrics[sc].DroppedPacketsBusyForwarder[p.TrafficType].Inc()
				l.pool.Put(p)
			}
			return false
		}
	}

	hdr := *hdrp
	payloadLen := len(p.RawPacket)

	p.RawPacket = p.WithHeader(len(hdr))
	copy(p.RawPacket, hdr)

	if l.is4 {
		ipTotalLen := headers.LenIPv4 + headers.LenUDP + payloadLen
		binary.BigEndian.PutUint16(p.RawPacket[headers.LenEth+2:], uint16(ipTotalLen))
		binary.BigEndian.PutUint16(
			p.RawPacket[headers.LenEth+headers.LenIPv4+4:],
			uint16(headers.LenUDP+payloadLen),
		)

		// IPv4 header checksum is always computed in software: 20 bytes is too cheap to
		// be worth offloading, and the NIC metadata path only covers the L4 checksum.
		p.RawPacket[headers.LenEth+10] = 0
		p.RawPacket[headers.LenEth+11] = 0
		csum := checksum.IPv4Header(p.RawPacket[headers.LenEth : headers.LenEth+headers.LenIPv4])
		binary.BigEndian.PutUint16(p.RawPacket[headers.LenEth+10:], csum)

		// IPv4 UDP checksum is optional (RFC 768), so we leave it zero.
		p.RawPacket[headers.LenEth+headers.LenIPv4+6] = 0
		p.RawPacket[headers.LenEth+headers.LenIPv4+7] = 0
	} else {
		udpTotalLen := headers.LenUDP + payloadLen
		binary.BigEndian.PutUint16(p.RawPacket[headers.LenEth+4:], uint16(udpTotalLen))
		udpOff := headers.LenEth + headers.LenIPv6
		binary.BigEndian.PutUint16(p.RawPacket[udpOff+4:], uint16(udpTotalLen))
		p.RawPacket[udpOff+6] = 0
		p.RawPacket[udpOff+7] = 0

		srcIP := l.localAddr.Addr().As16()
		dstIP := l.remoteAddr.Addr().As16()

		if csumOffload {
			// Seed the UDP checksum field with the pseudo-header partial sum;
			// the NIC folds in the rest at TX time.
			csum := checksum.UDP6Pseudo(srcIP, dstIP, udpTotalLen)
			binary.BigEndian.PutUint16(p.RawPacket[udpOff+6:], csum)
		} else {
			csum := checksum.UDP6(srcIP, dstIP,
				p.RawPacket[udpOff:udpOff+headers.LenUDP],
				p.RawPacket[udpOff+headers.LenUDP:])
			binary.BigEndian.PutUint16(p.RawPacket[udpOff+6:], csum)
		}
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

	// Start the netlink watcher before the first lookup,
	// so an update that arrives while we probe is not missed.
	l.neighbors.start(l.pool)

	peerIP := l.remoteAddr.Addr()
	l.neighbors.seekNeighbor(&peerIP)

	if l.bfdSession == nil {
		return
	}
	go func() {
		defer log.HandlePanic()
		// A BFD packet sent before the peer MAC is known is dropped,
		// and the session then waits a full detection interval for the next one.
		// Nothing else probes while the session is down, hence the wait here.
		if !l.awaitNeighbor(peerIP) {
			return
		}
		if err := l.bfdSession.Run(ctx); err != nil &&
			!errors.Is(err, bfd.ErrAlreadyRunning) {
			log.Error("BFD session failed to start",
				"remote address", l.remoteAddr,
				"err", err)
		}
	}()
}

// awaitNeighbor blocks until the peer MAC is resolved, re-probing on a timer.
// It reports false when the link stops first.
func (l *linkPTP) awaitNeighbor(peerIP netip.Addr) bool {
	t := time.NewTicker(neighborRetryInterval)
	defer t.Stop()
	for {
		if l.neighbors.resolved(peerIP) {
			return true
		}
		select {
		case <-l.neighborUpdated:
		case <-t.C:
			l.neighbors.seekNeighbor(&peerIP)
		case <-l.stopped:
			return false
		}
	}
}

func (l *linkPTP) stop() {
	if wasRunning := l.running.Swap(false); wasRunning {
		close(l.stopped)
	}
	if l.bfdSession != nil {
		l.bfdSession.Close()
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

// sendQueued sends the packets that waited for the peer's MAC address.
// Callers must not hold [neighborCache.lock].
// dropPackets counts packets the neighbor cache gave up on and frees them.
func (l *linkPTP) dropPackets(pkts []*router.Packet) {
	for _, p := range pkts {
		sc := router.ClassOfSize(len(p.RawPacket))
		l.metrics[sc].DroppedPacketsBusyForwarder[p.TrafficType].Inc()
		l.pool.Put(p)
	}
}

func (l *linkPTP) sendQueued() {
	for _, p := range l.neighbors.takeQueue(l.remoteAddr.Addr()) {
		l.Send(p)
	}
}

func (l *linkPTP) Send(p *router.Packet) bool {
	// Compute connection index from SCION payload BEFORE
	// [linkPTP.finishPacket] prepends headers.
	connIdx := computeConnIdx(p.RawPacket, len(l.txConns), l.seed)
	if !l.finishPacket(p, l.txConns[connIdx].csumOffload) {
		return false
	}
	select {
	case l.txConns[connIdx].queue <- p:
	default:
		sc := router.ClassOfSize(len(p.RawPacket))
		l.metrics[sc].DroppedPacketsBusyForwarder[p.TrafficType].Inc()
		l.pool.Put(p)
		return false
	}
	return true
}

func (l *linkPTP) SendBlocking(p *router.Packet) {
	// Compute connection index from SCION payload BEFORE
	// [linkPTP.finishPacket] prepends headers.
	connIdx := computeConnIdx(p.RawPacket, len(l.txConns), l.seed)
	if l.finishPacket(p, l.txConns[connIdx].csumOffload) {
		l.txConns[connIdx].queue <- p
	}
}

func (l *linkPTP) receive(p *router.Packet) {
	receivePacket(p, l, l.metrics, l.procQs, l.seed, l.pool)
}

func newPtpLinkExternal(
	localAddr *netip.AddrPort,
	remoteAddr *netip.AddrPort,
	rxConns, txConns []*udpConnection,
	bfd *bfd.Session,
	ifID uint16,
	conf NeighborConfig,
	metrics *router.InterfaceMetrics,
) *linkPTP {
	l := &linkPTP{
		localAddr:       localAddr,
		remoteAddr:      remoteAddr,
		rxConns:         rxConns,
		txConns:         txConns,
		metrics:         metrics,
		bfdSession:      bfd,
		neighborUpdated: make(chan struct{}, 1),
		stopped:         make(chan struct{}),
		scope:           router.External,
		seed:            txConns[0].seed,
		ifID:            ifID,
		is4:             localAddr.Addr().Is4(),
	}
	l.neighbors = newNeighborCache(
		"extTo_"+remoteAddr.String(),
		txConns[0].localMAC,
		localAddr.Addr(),
		txConns[0].ifIndex,
		conf,
		func(netip.Addr) {
			// Rebuild the header on the next packet, wake [linkPTP.awaitNeighbor],
			// and send what waited for the address.
			l.header.Store(nil)
			select {
			case l.neighborUpdated <- struct{}{}:
			default:
			}
			l.sendQueued()
		},
	)
	l.neighbors.onDrop = l.dropPackets

	// Register this link in all RX connections so any RX queue can dispatch to it.
	ft := fourTuple{
		src: addrPort{ip: remoteAddr.Addr(), port: remoteAddr.Port()},
		dst: addrPort{ip: localAddr.Addr(), port: localAddr.Port()},
	}
	for _, c := range rxConns {
		c.ptpLinks[ft] = l
	}

	log.Debug("***** AF_XDP Link", "scope", "external", "local", localAddr,
		"localMAC", txConns[0].localMAC, "remote", remoteAddr,
		"rx_queues", len(rxConns), "tx_queues", len(txConns))
	return l
}

func newPtpLinkSibling(
	localAddr *netip.AddrPort,
	remoteAddr *netip.AddrPort,
	rxConns, txConns []*udpConnection,
	bfd *bfd.Session,
	conf NeighborConfig,
	metrics *router.InterfaceMetrics,
) *linkPTP {
	l := &linkPTP{
		localAddr:       localAddr,
		remoteAddr:      remoteAddr,
		rxConns:         rxConns,
		txConns:         txConns,
		metrics:         metrics,
		bfdSession:      bfd,
		neighborUpdated: make(chan struct{}, 1),
		stopped:         make(chan struct{}),
		scope:           router.Sibling,
		seed:            txConns[0].seed,
		ifID:            0,
		is4:             localAddr.Addr().Is4(),
	}
	l.neighbors = newNeighborCache(
		"sibTo_"+remoteAddr.String(),
		txConns[0].localMAC,
		localAddr.Addr(),
		txConns[0].ifIndex,
		conf,
		func(netip.Addr) {
			// Rebuild the header on the next packet, wake [linkPTP.awaitNeighbor],
			// and send what waited for the address.
			l.header.Store(nil)
			select {
			case l.neighborUpdated <- struct{}{}:
			default:
			}
			l.sendQueued()
		},
	)
	l.neighbors.onDrop = l.dropPackets

	// Register this link in all RX connections so any RX queue can dispatch to it.
	ft := fourTuple{
		src: addrPort{ip: remoteAddr.Addr(), port: remoteAddr.Port()},
		dst: addrPort{ip: localAddr.Addr(), port: localAddr.Port()},
	}
	for _, c := range rxConns {
		c.ptpLinks[ft] = l
	}

	log.Debug("***** AF_XDP Link", "scope", "sibling", "local", localAddr,
		"localMAC", txConns[0].localMAC, "remote", remoteAddr,
		"rx_queues", len(rxConns), "tx_queues", len(txConns))
	return l
}

func (l *linkPTP) String() string {
	scope := "External"
	if l.scope == router.Sibling {
		scope = "Sibling"
	}
	return fmt.Sprintf("%s: local: %s remote: %s rx_queues: %d tx_queues: %d",
		scope, l.localAddr, l.remoteAddr, len(l.rxConns), len(l.txConns))
}
