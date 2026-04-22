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
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/bfd"
	"github.com/scionproto/scion/router/underlayproviders/afxdpudpip/internal/checksum"
	"github.com/scionproto/scion/router/underlayproviders/afxdpudpip/internal/headers"
)

// linkInternal is a link without a fixed remote address.
// The destination is determined per-packet via Resolve().
// Multiple AF_XDP sockets (one per NIC queue) are used for parallel TX/RX.
// TX packets are routed to sockets via a flow hash to prevent reordering.
type linkInternal struct {
	procQs           []chan *router.Packet
	pool             router.PacketPool
	localAddr        *netip.AddrPort
	rxConns          []*udpConnection
	txConns          []*udpConnection
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

	// Cached header template (no dest MAC/IP/port - patched per packet).
	header []byte
}

// getRemoteAddr extracts the destination IP and port from the packet's head bytes.
func getRemoteAddr(p *router.Packet, is4 bool) ([]byte, uint16) {
	if is4 {
		bh := p.HeadBytes(6)
		return bh[:4], binary.BigEndian.Uint16(bh[4:6])
	}
	bh := p.HeadBytes(18)
	return bh[:16], binary.BigEndian.Uint16(bh[16:18])
}

// setRemoteAddr stores the destination IP and port in the packet's head bytes.
func setRemoteAddr(p *router.Packet, ip []byte, port uint16) {
	bh := p.HeadBytes(len(ip) + 2)
	copy(bh, ip)
	binary.BigEndian.PutUint16(bh[len(ip):], port)
}

// packHeader builds the header template during initialization.
// The destination MAC, IP, and port are left as zeros and patched per-packet.
func (l *linkInternal) packHeader() {
	srcIP := l.localAddr.Addr()
	srcPort := l.localAddr.Port()

	if l.is4 {
		l.header = make([]byte, headers.LenEth+headers.LenIPv4+headers.LenUDP)

		// Ethernet: dst MAC (zero, patched later), src MAC, IPv4 ethertype
		copy(l.header[0:6], zeroMacAddr[:])
		copy(l.header[6:12], l.txConns[0].localMAC)
		binary.BigEndian.PutUint16(l.header[12:14], headers.EtherTypeIPv4)

		// IPv4 header template
		headers.BuildIPv4(l.header[headers.LenEth:], srcIP.As4(), [4]byte{}, 0)

		// UDP header template (only src port known)
		headers.BuildUDP(l.header[headers.LenEth+headers.LenIPv4:], srcPort, 0, 0)

	} else {
		l.header = make([]byte, headers.LenEth+headers.LenIPv6+headers.LenUDP)

		// Ethernet: dst MAC (zero, patched later), src MAC, IPv6 ethertype
		copy(l.header[0:6], zeroMacAddr[:])
		copy(l.header[6:12], l.txConns[0].localMAC)
		binary.BigEndian.PutUint16(l.header[12:14], headers.EtherTypeIPv6)

		// IPv6 header template
		headers.BuildIPv6(l.header[headers.LenEth:], srcIP.As16(), [16]byte{}, 0)

		// UDP header template
		headers.BuildUDP(l.header[headers.LenEth+headers.LenIPv6:], srcPort, 0, 0)
	}
}

// finishPacket prepends headers and patches destination + lengths + checksums.
// On success (true), the packet is ready to send and the caller owns it.
// On failure (false), the packet has already been disposed of (backlogged or
// returned to pool); the caller must not touch it.
func (l *linkInternal) finishPacket(p *router.Packet, csumOffload bool) bool {
	dstIPBytes, dstPort := getRemoteAddr(p, l.is4)
	dstIP, ok := netip.AddrFromSlice(dstIPBytes)
	if !ok {
		log.Debug("Dropping packet with broken remote address", "raw", dstIPBytes)
		sc := router.ClassOfSize(len(p.RawPacket))
		l.metrics[sc].DroppedPacketsInvalid.Inc()
		l.pool.Put(p)
		return false
	}

	// Resolve destination MAC
	l.neighbors.lock.Lock()
	dstMac, backlog := l.neighbors.get(dstIP)
	l.neighbors.lock.Unlock()

	if dstMac == nil {
		select {
		case backlog <- p:
		default:
			sc := router.ClassOfSize(len(p.RawPacket))
			l.metrics[sc].DroppedPacketsBusyForwarder[p.TrafficType].Inc()
			l.pool.Put(p)
		}
		return false
	}

	payloadLen := len(p.RawPacket)

	p.RawPacket = p.WithHeader(len(l.header))
	copy(p.RawPacket, l.header)
	copy(p.RawPacket[0:6], dstMac[:])

	if l.is4 {
		copy(p.RawPacket[headers.LenEth+16:headers.LenEth+20], dstIPBytes)

		ipTotalLen := headers.LenIPv4 + headers.LenUDP + payloadLen
		binary.BigEndian.PutUint16(p.RawPacket[headers.LenEth+2:], uint16(ipTotalLen))
		binary.BigEndian.PutUint16(p.RawPacket[headers.LenEth+headers.LenIPv4+2:], dstPort)
		binary.BigEndian.PutUint16(
			p.RawPacket[headers.LenEth+headers.LenIPv4+4:], uint16(headers.LenUDP+payloadLen),
		)

		// IPv4 header checksum is always computed in software: 20 bytes is too
		// cheap to be worth offloading, and the NIC metadata path only covers
		// the L4 checksum.
		p.RawPacket[headers.LenEth+10] = 0
		p.RawPacket[headers.LenEth+11] = 0
		csum := checksum.IPv4Header(p.RawPacket[headers.LenEth : headers.LenEth+headers.LenIPv4])
		binary.BigEndian.PutUint16(p.RawPacket[headers.LenEth+10:], csum)

		// IPv4 UDP checksum is optional (RFC 768), so we leave it zero.
		p.RawPacket[headers.LenEth+headers.LenIPv4+6] = 0
		p.RawPacket[headers.LenEth+headers.LenIPv4+7] = 0
	} else {
		copy(p.RawPacket[headers.LenEth+24:headers.LenEth+40], dstIPBytes)

		udpTotalLen := headers.LenUDP + payloadLen
		binary.BigEndian.PutUint16(p.RawPacket[headers.LenEth+4:], uint16(udpTotalLen))
		udpOff := headers.LenEth + headers.LenIPv6
		binary.BigEndian.PutUint16(p.RawPacket[udpOff+2:], dstPort)
		binary.BigEndian.PutUint16(p.RawPacket[udpOff+4:], uint16(udpTotalLen))
		p.RawPacket[udpOff+6] = 0
		p.RawPacket[udpOff+7] = 0

		srcIP := l.localAddr.Addr().As16()
		dstIP6 := dstIP.As16()

		if csumOffload {
			// Seed the UDP checksum field with the pseudo-header partial sum; the
			// NIC folds in the rest at TX time.
			csum := checksum.UDP6Pseudo(srcIP, dstIP6, udpTotalLen)
			binary.BigEndian.PutUint16(p.RawPacket[udpOff+6:], csum)
		} else {
			csum := checksum.UDP6(srcIP, dstIP6,
				p.RawPacket[udpOff:udpOff+headers.LenUDP],
				p.RawPacket[udpOff+headers.LenUDP:])
			binary.BigEndian.PutUint16(p.RawPacket[udpOff+6:], csum)
		}
	}
	return true
}

func (l *linkInternal) start(
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

	// Announce ourselves
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

func (l *linkInternal) stop() {
	wasRunning := l.running.Swap(false)
	if wasRunning {
		select {
		case l.backlogCheck <- netip.Addr{}:
		default:
		}
		<-l.sendBacklogDone
	}
	l.neighbors.stop()
}

func (l *linkInternal) IfID() uint16 {
	return 0
}

func (l *linkInternal) Metrics() *router.InterfaceMetrics {
	return l.metrics
}

func (l *linkInternal) Scope() router.LinkScope {
	return router.Internal
}

func (l *linkInternal) BFDSession() *bfd.Session {
	return nil
}

func (l *linkInternal) IsUp() bool {
	return true
}

// Resolve updates the packet's underlay destination according to the given SCION address.
func (l *linkInternal) Resolve(p *router.Packet, dst addr.Host, port uint16) error {
	var dstAddr netip.Addr
	switch dst.Type() {
	case addr.HostTypeSVC:
		a, ok := l.svc.Any(dst.SVC().Base())
		if !ok {
			return router.ErrNoSVCBackend
		}
		dstAddr = a.Addr()
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
		panic(fmt.Sprintf("unexpected address type: %s", dst.Type()))
	}

	// Port redirection for dispatcher
	if port < l.dispatchStart || port > l.dispatchEnd {
		port = l.dispatchRedirect
	}

	setRemoteAddr(p, dstAddr.AsSlice(), port)
	return nil
}

func (l *linkInternal) sendBacklog(dstAddr netip.Addr) {
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
			connIdx := computeConnIdx(p.RawPacket, len(l.txConns), l.seed)
			if !l.finishPacket(p, l.txConns[connIdx].csumOffload) {
				givenup = true
				continue
			}
			select {
			case l.txConns[connIdx].queue <- p:
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

func (l *linkInternal) Send(p *router.Packet) bool {
	// Compute connection index from SCION payload BEFORE finishPacket prepends headers.
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

func (l *linkInternal) SendBlocking(p *router.Packet) {
	// Compute connection index from SCION payload BEFORE finishPacket prepends headers.
	connIdx := computeConnIdx(p.RawPacket, len(l.txConns), l.seed)
	if l.finishPacket(p, l.txConns[connIdx].csumOffload) {
		l.txConns[connIdx].queue <- p
	}
}

func (l *linkInternal) receive(p *router.Packet) {
	receivePacket(p, l, l.metrics, l.procQs, l.seed, l.pool)
}

func newInternalLink(
	localAddr *netip.AddrPort,
	rxConns, txConns []*udpConnection,
	svc *router.Services[netip.AddrPort],
	dispatchStart, dispatchEnd, dispatchRedirect uint16,
	metrics *router.InterfaceMetrics,
) *linkInternal {
	il := &linkInternal{
		localAddr:        localAddr,
		rxConns:          rxConns,
		txConns:          txConns,
		metrics:          metrics,
		svc:              svc,
		backlogCheck:     make(chan netip.Addr, 1),
		sendBacklogDone:  make(chan struct{}),
		seed:             txConns[0].seed,
		dispatchStart:    dispatchStart,
		dispatchEnd:      dispatchEnd,
		dispatchRedirect: dispatchRedirect,
		is4:              localAddr.Addr().Is4(),
	}
	il.neighbors = newNeighborCache(
		"internal",
		txConns[0].localMAC,
		localAddr.Addr(),
		txConns[0].ifIndex,
		func(ip netip.Addr) {
			select {
			case il.backlogCheck <- ip:
			default:
			}
		},
	)
	il.packHeader()

	// Register this link in all RX connections so any RX queue can dispatch to it.
	ap := addrPort{ip: localAddr.Addr(), port: localAddr.Port()}
	for _, c := range rxConns {
		c.intLinks[ap] = il
	}

	log.Debug("***** AF_XDP Link", "scope", "internal", "local", localAddr,
		"localMAC", txConns[0].localMAC,
		"rx_queues", len(rxConns), "tx_queues", len(txConns))
	return il
}

func (l *linkInternal) String() string {
	return fmt.Sprintf("Internal: local: %s rx_queues: %d tx_queues: %d",
		l.localAddr, len(l.rxConns), len(l.txConns))
}
