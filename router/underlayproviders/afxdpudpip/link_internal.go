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

//go:build linux

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
		l.header = make([]byte, ethLen+ipv4Len+udpLen)

		// Ethernet: dst MAC (zero, patched later), src MAC, IPv4 ethertype
		copy(l.header[0:6], zeroMacAddr[:])
		copy(l.header[6:12], l.txConns[0].localMAC)
		binary.BigEndian.PutUint16(l.header[12:14], 0x0800)

		// IPv4 header template
		buildIPv4Header(l.header[ethLen:], srcIP.As4(), [4]byte{}, 0)

		// UDP header template (only src port known)
		buildUDPHeader(l.header[ethLen+ipv4Len:], srcPort, 0, 0)

	} else {
		l.header = make([]byte, ethLen+ipv6Len+udpLen)

		// Ethernet: dst MAC (zero, patched later), src MAC, IPv6 ethertype
		copy(l.header[0:6], zeroMacAddr[:])
		copy(l.header[6:12], l.txConns[0].localMAC)
		binary.BigEndian.PutUint16(l.header[12:14], 0x86DD)

		// IPv6 header template
		buildIPv6Header(l.header[ethLen:], srcIP.As16(), [16]byte{}, 0)

		// UDP header template
		buildUDPHeader(l.header[ethLen+ipv6Len:], srcPort, 0, 0)
	}
}

// finishPacket prepends headers and patches destination + lengths + checksums.
// On success (true), the packet is ready to send and the caller owns it.
// On failure (false), the packet has already been disposed of (backlogged or
// returned to pool); the caller must not touch it.
func (l *linkInternal) finishPacket(p *router.Packet) bool {
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

	// Prepend the header template
	p.RawPacket = p.WithHeader(len(l.header))
	copy(p.RawPacket, l.header)

	// Patch destination MAC
	copy(p.RawPacket[0:6], dstMac[:])

	if l.is4 {
		// Patch destination IP
		copy(p.RawPacket[ethLen+16:ethLen+20], dstIPBytes)

		// Fix IPv4 total length
		ipTotalLen := ipv4Len + udpLen + payloadLen
		binary.BigEndian.PutUint16(p.RawPacket[ethLen+2:], uint16(ipTotalLen))

		// Fix destination port
		binary.BigEndian.PutUint16(p.RawPacket[ethLen+ipv4Len+2:], dstPort)

		// Fix UDP length
		binary.BigEndian.PutUint16(
			p.RawPacket[ethLen+ipv4Len+4:], uint16(udpLen+payloadLen),
		)

		// Recompute IPv4 header checksum
		p.RawPacket[ethLen+10] = 0
		p.RawPacket[ethLen+11] = 0
		csum := ipv4Checksum(p.RawPacket[ethLen : ethLen+ipv4Len])
		binary.BigEndian.PutUint16(p.RawPacket[ethLen+10:], csum)

		// IPv4 UDP checksum is optional
		p.RawPacket[ethLen+ipv4Len+6] = 0
		p.RawPacket[ethLen+ipv4Len+7] = 0
	} else {
		// Patch destination IP
		copy(p.RawPacket[ethLen+24:ethLen+40], dstIPBytes)

		// Fix IPv6 payload length
		binary.BigEndian.PutUint16(p.RawPacket[ethLen+4:], uint16(udpLen+payloadLen))

		// Fix destination port
		udpOff := ethLen + ipv6Len
		binary.BigEndian.PutUint16(p.RawPacket[udpOff+2:], dstPort)

		// Fix UDP length
		binary.BigEndian.PutUint16(p.RawPacket[udpOff+4:], uint16(udpLen+payloadLen))

		// Zero checksum for computation
		p.RawPacket[udpOff+6] = 0
		p.RawPacket[udpOff+7] = 0

		// Compute IPv6 UDP checksum (mandatory)
		srcIP := l.localAddr.Addr().As16()
		dstIP6 := dstIP.As16()
		csum := udp6Checksum(srcIP, dstIP6,
			p.RawPacket[udpOff:udpOff+udpLen],
			p.RawPacket[udpOff+udpLen:])
		binary.BigEndian.PutUint16(p.RawPacket[udpOff+6:], csum)
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
			if !l.finishPacket(p) {
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
	if !l.finishPacket(p) {
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
	if l.finishPacket(p) {
		l.txConns[connIdx].queue <- p
	}
}

func (l *linkInternal) receive(p *router.Packet) {
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
