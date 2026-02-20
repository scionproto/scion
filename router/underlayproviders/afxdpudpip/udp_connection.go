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
	"crypto/rand"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/private/underlay/afxdp"
	"github.com/scionproto/scion/router"
)

// addrPort is like netip.AddrPort but with mutable (for us) fields.
// This saves an address copy.
type addrPort struct {
	ip   netip.Addr
	port uint16
}

// fourTuple aggregates src and dst addrPorts.
type fourTuple struct {
	src addrPort
	dst addrPort
}

// udpConnection manages an AF_XDP socket bound to a specific interface and queue.
// It handles RX/TX packet processing with zero-copy UMEM frames.
// The xdpInterface is shared across connections on the same NIC and is NOT
// owned by this connection (closed by the underlay).
type udpConnection struct {
	localMAC     net.HardwareAddr
	xdpInterface *afxdp.Interface
	socket       *afxdp.Socket
	name         string                // For logs.
	ptpLinks     map[fourTuple]udpLink // Link map for specific remote addresses.
	intLinks     map[addrPort]udpLink  // Link map for unknown remote addresses.

	// queue is the outgoing packet queue (packets with headers prepended)
	queue        chan *router.Packet
	metrics      *router.InterfaceMetrics
	receiverDone chan struct{}
	senderDone   chan struct{}
	seed         uint32
	running      atomic.Bool
	queueID      uint32
	ifIndex      int // Kernel interface index for neighbor filtering.
}

// start puts the connection in the running state.
func (u *udpConnection) start(batchSize int, pool router.PacketPool) {
	wasRunning := u.running.Swap(true)
	if wasRunning {
		return
	}

	// Receiver task
	go func() {
		defer log.HandlePanic()
		u.receive(pool)
		close(u.receiverDone)
	}()

	// Sender task
	go func() {
		defer log.HandlePanic()
		u.send(batchSize, pool)
		close(u.senderDone)
	}()
}

// stop puts the connection in the stopped state.
// Only closes the socket; the shared xdpInterface is closed by the underlay.
func (u *udpConnection) stop() {
	wasRunning := u.running.Swap(false)

	if wasRunning {
		close(u.queue) // Unblock sender
		<-u.receiverDone
		<-u.senderDone
		if u.socket != nil {
			u.socket.Close()
		}
	}
}

// receive processes incoming packets from the AF_XDP socket.
func (u *udpConnection) receive(pool router.PacketPool) {
	// Pre-allocate frame buffer for batch receive.
	frameBuffer := make([]afxdp.Frame, defaultBatchSize)

	// Minimum headroom assuming IPv4 (we adjust for actual headers later).
	minHeadRoom := ethLen + ipv4Len + udpLen

	// Reusable packet buffer - reset and reuse until delivered.
	p := pool.Get()

	for u.running.Load() {
		// Wait for packets with a timeout.
		if err := u.socket.Wait(200); err != nil {
			continue
		}

		// Receive batch of frames.
		frames := u.socket.Receive(frameBuffer)
		if len(frames) == 0 {
			continue
		}

		for _, frame := range frames {
			pool.ResetPacket(p)

			data := p.WithHeader(minHeadRoom)

			// Copy frame data to packet buffer.
			if len(frame.Buf) > len(data) {
				sc := router.ClassOfSize(len(frame.Buf))
				u.metrics[sc].DroppedPacketsInvalid.Inc()
				u.socket.Release(frame)
				continue
			}
			copy(data, frame.Buf)
			data = data[:len(frame.Buf)]

			// Release frame back to UMEM immediately.
			u.socket.Release(frame)

			// Parse the packet and dispatch to appropriate link.
			if u.dispatchPacket(p, data) {
				p = pool.Get() // Need a fresh packet buffer
			} else {
				sc := router.ClassOfSize(len(data))
				u.metrics[sc].DroppedPacketsInvalid.Inc()
			}
		}
	}

	pool.Put(p)
}

// dispatchPacket parses and dispatches a received packet to the appropriate link.
// Returns true if the packet was delivered (caller needs new buffer).
func (u *udpConnection) dispatchPacket(p *router.Packet, data []byte) bool {
	if len(data) < ethLen {
		return false
	}

	// Parse Ethernet header (raw).
	etherType := uint16(data[12])<<8 | uint16(data[13])

	var srcDst fourTuple
	var srcIPBytes []byte
	var payloadOffset int

	switch etherType {
	case 0x0800: // IPv4
		if len(data) < ethLen+ipv4Len {
			return false
		}
		ipHdrLen := int(data[ethLen]&0x0F) * 4
		if ipHdrLen < ipv4Len || len(data) < ethLen+ipHdrLen+udpLen {
			return false
		}
		if data[ethLen+9] != 17 { // Not UDP
			return false
		}

		srcDst.src.ip = netip.AddrFrom4([4]byte(data[ethLen+12 : ethLen+16]))
		srcDst.dst.ip = netip.AddrFrom4([4]byte(data[ethLen+16 : ethLen+20]))
		srcIPBytes = data[ethLen+12 : ethLen+16]

		udpStart := ethLen + ipHdrLen
		payloadOffset = udpStart + udpLen
		srcDst.src.port = uint16(data[udpStart])<<8 | uint16(data[udpStart+1])
		srcDst.dst.port = uint16(data[udpStart+2])<<8 | uint16(data[udpStart+3])

	case 0x86DD: // IPv6
		if len(data) < ethLen+ipv6Len+udpLen {
			return false
		}
		if data[ethLen+6] != 17 { // Not UDP
			return false
		}

		srcDst.src.ip = netip.AddrFrom16([16]byte(data[ethLen+8 : ethLen+24]))
		srcDst.dst.ip = netip.AddrFrom16([16]byte(data[ethLen+24 : ethLen+40]))
		srcIPBytes = data[ethLen+8 : ethLen+24]

		udpStart := ethLen + ipv6Len
		payloadOffset = udpStart + udpLen
		srcDst.src.port = uint16(data[udpStart])<<8 | uint16(data[udpStart+1])
		srcDst.dst.port = uint16(data[udpStart+2])<<8 | uint16(data[udpStart+3])

	default:
		// ARP/NDP are handled by kernel via XDP_PASS
		return false
	}

	if len(data) < payloadOffset {
		return false
	}

	// Set packet payload (SCION data starts after UDP header).
	p.RawPacket = data[payloadOffset:]

	// Try PTP links first (external/sibling with known remote).
	if l, found := u.ptpLinks[srcDst]; found {
		l.receive(p)
		return true
	}

	// Try internal links (unknown remote).
	if l, found := u.intLinks[srcDst.dst]; found {
		setRemoteAddr(p, srcIPBytes, srcDst.src.port)
		l.receive(p)
		return true
	}

	return false
}

// send processes outgoing packets from the queue by copying them into UMEM frames.
func (u *udpConnection) send(batchSize int, pool router.PacketPool) {
	pkts := make([]*router.Packet, batchSize)
	sent := make([]*router.Packet, 0, batchSize)
	metrics := u.metrics

	for u.running.Load() {
		// Block on first packet.
		pkt, ok := <-u.queue
		if !ok {
			break
		}
		pkts[0] = pkt
		toWrite := 1

		// Batch more packets (non-blocking).
		for toWrite < batchSize {
			select {
			case pkt, ok = <-u.queue:
				if !ok {
					goto flush
				}
				pkts[toWrite] = pkt
				toWrite++
			default:
				goto flush
			}
		}

	flush:
		if toWrite == 0 {
			continue
		}

		sent = sent[:0]
		for i := 0; i < toWrite; i++ {
			frame := u.socket.NextFrame()
			if frame.Buf == nil {
				// No free frames; drop remaining packets.
				for j := i; j < toWrite; j++ {
					sc := router.ClassOfSize(len(pkts[j].RawPacket))
					metrics[sc].DroppedPacketsBusyForwarder[pkts[j].TrafficType].Inc()
					pool.Put(pkts[j])
				}
				break
			}

			raw := pkts[i].RawPacket
			if len(raw) > len(frame.Buf) {
				sc := router.ClassOfSize(len(raw))
				metrics[sc].DroppedPacketsInvalid.Inc()
				pool.Put(pkts[i])
				continue
			}

			copy(frame.Buf[:len(raw)], raw)
			if err := u.socket.Submit(frame.Addr, uint32(len(raw))); err != nil {
				log.Debug("AF_XDP submit error", "err", err)
				sc := router.ClassOfSize(len(raw))
				metrics[sc].DroppedPacketsBusyForwarder[pkts[i].TrafficType].Inc()
				pool.Put(pkts[i])
				continue
			}
			sent = append(sent, pkts[i])
		}

		// Flush TX ring.
		if len(sent) > 0 {
			if err := u.socket.FlushTx(); err != nil {
				log.Debug("AF_XDP flush error", "err", err)
			}

			// Update metrics and return sent packets to pool.
			router.UpdateOutputMetrics(metrics, sent)
			for _, p := range sent {
				pool.Put(p)
			}
		}
	}
}

// makeHashSeed creates a new random hash seed for processor queue distribution.
func makeHashSeed() uint32 {
	hashSeed := router.Fnv1aOffset32
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		panic("Error while generating random value")
	}
	for _, c := range randomBytes {
		hashSeed = router.HashFNV1a(hashSeed, c)
	}
	return hashSeed
}

// newUdpConnection creates a new AF_XDP connection on the given interface and queue.
// The xdpInterface is shared across connections on the same NIC and must not be
// closed by this connection.
func newUdpConnection(
	intf net.Interface,
	queueID uint32,
	qSize int,
	connOpener ConnOpener,
	xdpInterface *afxdp.Interface,
	metrics *router.InterfaceMetrics,
) (*udpConnection, error) {
	// Open AF_XDP socket on the specified queue.
	socket, err := connOpener.Open(intf.Index, queueID, xdpInterface)
	if err != nil {
		return nil, err
	}

	hwAddr := intf.HardwareAddr
	if len(hwAddr) == 0 {
		hwAddr = zeroMacAddr[:]
	}

	queue := make(chan *router.Packet, qSize)

	return &udpConnection{
		localMAC:     hwAddr,
		xdpInterface: xdpInterface,
		socket:       socket,
		name:         intf.Name,
		ptpLinks:     make(map[fourTuple]udpLink),
		intLinks:     make(map[addrPort]udpLink),
		queue:        queue,
		metrics:      metrics,
		seed:         makeHashSeed(),
		receiverDone: make(chan struct{}),
		senderDone:   make(chan struct{}),
		queueID:      queueID,
		ifIndex:      intf.Index,
	}, nil
}
