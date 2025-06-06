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
	"encoding/binary"
	"math/rand"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/private/underlay/ebpf"
	"github.com/scionproto/scion/router"
)

var ndpMcastPrefix = []byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1, 0xff}

// udpConnection is a TPacket connection with a sending queue and a demultiplexer. The rest is
// about logs and metrics. This allows UDP connections to be shared between links, which is the
// norm in this case; since a raw socket receives traffic for all ports.
type udpConnection struct {
	localMAC     net.HardwareAddr
	name         string                     // for logs. It's more informative than ifID.
	link         udpLink                    // Default Link for ingest.
	links        map[netip.AddrPort]udpLink // Link map for ingest from specific remote addresses.
	afp          *afpacket.TPacket
	filter       *ebpf.FilterHandle
	queue        chan *router.Packet
	metrics      *router.InterfaceMetrics
	receiverDone chan struct{}
	senderDone   chan struct{}
	seed         uint32
	running      atomic.Bool
}

// start puts the connection in the running state. In that state, the connection can deliver
// incoming packets and ignores packets present on its input channel.
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

	// Forwarder task
	go func() {
		defer log.HandlePanic()
		u.send(batchSize, pool)
		close(u.senderDone)
	}()
}

// stop() puts the connection in the stopped state. In that state, the connection no longer delivers
// incoming packets and ignores packets present on its input channel. The connection is fully
// stopped when this method returns. The first call to stop is acted upon regardless of how many
// times start was called.
func (u *udpConnection) stop() {
	wasRunning := u.running.Swap(false)

	if wasRunning {
		u.afp.Close()    // Unblock receiver
		u.filter.Close() // Discard the filter progs
		close(u.queue)   // Unblock sender
		<-u.receiverDone
		<-u.senderDone
	}
}

func (u *udpConnection) handleArp(arp *layers.ARP) {
	if arp.AddrType != layers.LinkTypeEthernet ||
		arp.HwAddressSize != 6 ||
		arp.Protocol != layers.EthernetTypeIPv4 ||
		arp.ProtAddressSize != 4 {
		return
	}
	targetIP := netip.AddrFrom4([4]byte(arp.DstProtAddress))
	senderIP := netip.AddrFrom4([4]byte(arp.SourceProtAddress))

	// Get the MACs out of the packet too; it's all just slices referring to it.
	// Reduce them to just 6 bytes while we are at it.
	if len(arp.SourceHwAddress) != 6 {
		return
	}
	senderMAC := [6]byte(arp.SourceHwAddress)

	// TODO(jiceatscion): ignore gratuitous reqs
	isReq := (arp.Operation == layers.ARPRequest)

	// We have to pass all requests to all links. Sometimes the sender uses an IP address
	// that we don't know about (e.g. the traffic generator uses interfaces with a different
	// IP assigned - which the arp lib then uses to make requests).
	for _, l := range u.links {
		l.handleNeighbor(isReq, targetIP, senderIP, senderMAC)
	}
	if u.link != nil {
		u.link.handleNeighbor(isReq, targetIP, senderIP, senderMAC)
	}
}

// Handle NDP minimally.
// Terminology just as shitty as ARP; just different - Summary of the protocol:
//
// |                     Sollicitations   |   advertisements
// ---------------------------------------------------------------
// IP to be resolved:    TargetAddress    |   TargetAddress
// IP of pkt sender:     from IP header   |   TargetAddress
// MAC to be found:      -                |   OptTargetAddress
// MAC of pkt sender:    OptSourceAddress |   -
func (u *udpConnection) handleV6NDP(icmp6 *layers.ICMPv6, srcIP netip.Addr) {
	data := icmp6.LayerPayload()
	var isReq bool
	var valid bool
	var targetIP netip.Addr
	var remoteMAC [6]byte

	switch icmp6.TypeCode {
	case layers.ICMPv6TypeNeighborSolicitation:
		var query layers.ICMPv6NeighborSolicitation
		if err := query.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			targetIP, valid = netip.AddrFromSlice(query.TargetAddress)
			if !valid {
				return
			}
		}
		isReq = true
		for _, opt := range query.Options {
			if opt.Type == layers.ICMPv6OptSourceAddress {
				if len(opt.Data) != 6 {
					return
				}
				remoteMAC = [6]byte(opt.Data)
			}
		}
	case layers.ICMPv6TypeNeighborAdvertisement:
		var response layers.ICMPv6NeighborAdvertisement
		if err := response.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			targetIP, valid = netip.AddrFromSlice(response.TargetAddress)
			if !valid {
				return
			}
			for _, opt := range response.Options {
				if opt.Type == layers.ICMPv6OptTargetAddress {
					if len(opt.Data) != 6 {
						return
					}
					remoteMAC = [6]byte(opt.Data)
				}
			}
		}
	default:
		return
	}

	// We have to pass all requests to all links. Sometimes the sender uses an IP address
	// that we don't know about (e.g. the traffic generator uses interfaces with a different
	// IP assigned - which the arp lib then uses to make requests).
	for _, l := range u.links {
		l.handleNeighbor(isReq, targetIP, srcIP, remoteMAC)
	}
	if u.link != nil {
		u.link.handleNeighbor(isReq, targetIP, srcIP, remoteMAC)
	}
}

func (u *udpConnection) receive(pool router.PacketPool) {
	// Since we do not know the real size of the IP header, we have to plan on it being short; so
	// our payload doesn't encroach on the headroom space. If the header is longer, then we will
	// leave more headroom than needed. We don't even know if we're getting v4 or v6. Assume v4.
	// As of this writing we do not expect extensions, so the actual headers should
	// never be greater than the biggest v4 header (14+60+8). Else, the packet hits the can.
	minHeadRoom := 14 + 20 + 8

	var ethLayer layers.Ethernet
	var arpLayer layers.ARP
	var icmp6Layer layers.ICMPv6
	var ipv4Layer layers.IPv4
	var ipv6Layer layers.IPv6
	var udpLayer layers.UDP
	var srcIP netip.Addr
	var validSrc bool

	// We'll reuse this one until we can deliver it. At which point, we fetch a fresh one.
	// pool.Reset is much cheaper than pool.Put/Get
	p := pool.Get()

	for u.running.Load() {
		// Since it may be recycled...
		pool.ResetPacket(p)

		data := p.WithHeader(minHeadRoom) // data now maps to where we dump the whole packet
		_, err := u.afp.ReadPacketDataTo(data)
		if err != nil {
			continue
		}
		// Now we need to figure out the real length of the headers and the src addr.
		if err := ethLayer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			continue
		}
		data = ethLayer.LayerPayload() // chop off the eth header
		switch ethLayer.EthernetType {
		case layers.EthernetTypeIPv4:
			if err := ipv4Layer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
				continue
			}
			if ipv4Layer.Protocol != layers.IPProtocolUDP {
				continue
			}
			// Retrieve src from the decoded IP layers.
			srcIP, validSrc = netip.AddrFromSlice(ipv4Layer.SrcIP)
			if !validSrc {
				// WTF?
				continue
			}
			data = ipv4Layer.LayerPayload() // chop off the ip header
		case layers.EthernetTypeIPv6:
			if err := ipv6Layer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
				continue
			}
			// Retrieve src from the decoded IP layers.
			srcIP, validSrc = netip.AddrFromSlice(ipv6Layer.SrcIP)
			if !validSrc {
				// WTF?
				continue
			}
			data = ipv6Layer.LayerPayload() // chop off the ip header
			if ipv6Layer.NextHeader == layers.IPProtocolICMPv6 {
				if err := icmp6Layer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
					u.handleV6NDP(&icmp6Layer, srcIP) // The packet stays with us.
				}
				continue
			} else if ipv6Layer.NextHeader != layers.IPProtocolUDP {
				// Not UPD either? Could be extensions. We don't expect any.
				continue
			}
		case layers.EthernetTypeARP:
			if err := arpLayer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
				u.handleArp(&arpLayer) // The packet stays with us.
			}
			continue
		default:
			continue
		}
		if err := udpLayer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			continue
		}

		// Demultiplex to a link. There is one connection per interface, so they are mostly shared
		// between links; including the internal link. The internal link catches all remote
		// addresses that no other link claims. That is what u.link is. Connections that are not
		// shared with the internal link do not have it as they should not accept packets from
		// unknown sources (but they might receive them: the ebpf filter only looks at port).
		srcAddr := netip.AddrPortFrom(srcIP, uint16(udpLayer.SrcPort))
		l := u.link
		if u.links != nil {
			if ll, found := u.links[srcAddr]; found {
				l = ll
			}
		}
		if l == nil {
			continue
		}

		// FIXME: it is very unfortunate that we end-up allocating the src addr
		// even in this implementation. Instead of using a netip.AddrPort, we could
		// point directly at some space in the packet buffer (not the header itself - it
		// gets overwritten by SCMP).
		p.RawPacket = udpLayer.LayerPayload() // chop off the udp header. The rest is SCION.
		l.receive(&srcAddr, p)
		p = pool.Get() // we need a fresh packet buffer now.
	}

	// We have to stop receiving. Return the unused packet to the pool to avoid creating
	// a memory leak (the process is not required to exit - e.g. in tests).
	pool.Put(p)
}

// TODO(jiceatscion): This way of doing things isn't efficient here. The mpktSender API was lifted
// from brload, where it made more sense than here...simplify by merging mst of mpktSender in-here.
func readUpTo(queue <-chan *router.Packet, n int, needsBlocking bool, pkts []*router.Packet) int {
	i := 0
	if needsBlocking {
		p, ok := <-queue
		if !ok {
			return i
		}
		pkts[i] = p
		i++
	}

	for ; i < n; i++ {
		select {
		case p, ok := <-queue:
			if !ok {
				return i
			}
			pkts[i] = p
		default:
			return i
		}
	}
	return i
}

var seropts = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

func (u *udpConnection) send(batchSize int, pool router.PacketPool) {
	// We use this somewhat like a ring buffer.
	pkts := make([]*router.Packet, batchSize)

	// We use this as a temporary container, but allocate it just once
	// to save on garbage handling. TODO(jiceatscion): should not be needed: modify mmsg.go.
	msgs := make([][]byte, batchSize)
	queue := u.queue
	sender := newMpktSender(u.afp)
	metrics := u.metrics
	toWrite := 0

	for u.running.Load() {
		// Top-up our batch.
		toWrite += readUpTo(queue, batchSize-toWrite, toWrite == 0, pkts[toWrite:])

		// Line the raw packets up for the sender.
		for i, p := range pkts[:toWrite] {
			msgs[i] = p.RawPacket
		}
		sender.setPkts(msgs[:toWrite])
		written, _ := sender.sendAll()
		if written < 0 {
			// WriteBatch returns -1 on error, we just consider this as
			// 0 packets written
			written = 0
		}
		router.UpdateOutputMetrics(metrics, pkts[:written])
		for _, p := range pkts[:written] {
			pool.Put(p)
		}
		if written != toWrite {
			// Only one is dropped at this time. We'll retry the rest.
			sc := router.ClassOfSize(len(pkts[written].RawPacket))
			metrics[sc].DroppedPacketsInvalid.Inc()
			pool.Put(pkts[written])
			toWrite -= (written + 1)
			// Shift the leftovers to the head of the buffers.
			for i := 0; i < toWrite; i++ {
				pkts[i] = pkts[i+written+1]
			}
		} else {
			toWrite = 0
		}
	}
}

// makeHashSeed creates a new random number to serve as hash seed.
// Each receive loop is associated with its own hash seed to compute
// the proc queue where a packet should be delivered. All links that share
// an underlying connection (therefore a receive loop) use the same hash seed.
func makeHashSeed() uint32 {
	hashSeed := fnv1aOffset32
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		panic("Error while generating random value")
	}
	for _, c := range randomBytes {
		hashSeed = hashFNV1a(hashSeed, c)
	}
	return hashSeed
}

func newUdpConnection(
	intf net.Interface,
	qSize int,
	connOpener ConnOpener,
	port uint16,
	metrics *router.InterfaceMetrics,
) (*udpConnection, error) {
	queue := make(chan *router.Packet, qSize)
	afp, filter, err := connOpener.Open(intf.Index, port)
	if err != nil {
		return nil, err
	}
	hwAddr := intf.HardwareAddr

	// Catering to tests that use a local IPv6 address on the loopback interface which has no mac
	// address assigned. We make one up and rely on the fact the everything bounces to everyone
	// anyway. Not sure how well the non-recipient routers will handle the junk traffic because we
	// don't filter it explicitly.
	if len(hwAddr) == 0 {
		num := rand.Uint32()
		hwAddr = net.HardwareAddr{0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(hwAddr, uint32(num))
		hwAddr[0] = 0x02
	}
	return &udpConnection{
		localMAC:     hwAddr,
		name:         intf.Name,
		afp:          afp,
		filter:       filter,
		queue:        queue,
		links:        make(map[netip.AddrPort]udpLink),
		metrics:      metrics,
		seed:         makeHashSeed(),
		receiverDone: make(chan struct{}),
		senderDone:   make(chan struct{}),
	}, nil
}
