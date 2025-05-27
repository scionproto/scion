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
	"crypto/rand"
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

// udpConnection is a TPacket connection with a sending queue and a demultiplexer. The rest is
// about logs and metrics. This allows UDP connections to be shared between links, which is the
// norm in this case; since a raw socket receives traffic for all ports.
type udpConnection struct {
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
	return &udpConnection{
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

func (u *udpConnection) receive(pool router.PacketPool) {
	log.Debug("Receive", "connection", u.name)

	// Since we do not know the real size of the IP header, we have to plan on it being short; so
	// our payload doesn't encroach on the headroom space. If the header is longer, then we will
	// leave more headroom than needed. We don't even know if we're getting v4 or v6. Assume v4.
	// As of this writing we do not expect extensions, so the actual headers should
	// never be greater than the biggest v4 header (14+60+8). Else, the packet hits the can.
	minHeadRoom := 14 + 20 + 8

	var ethLayer layers.Ethernet
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
		networkLayer := ethLayer.NextLayerType()
		data = ethLayer.LayerPayload() // chop off the eth header
		if ipv4Layer.CanDecode().Contains(networkLayer) {
			if err := ipv4Layer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
				continue
			}
			if !udpLayer.CanDecode().Contains(ipv4Layer.NextLayerType()) {
				continue
			}
			// Retrieve src from the decoded IP layers.
			srcIP, validSrc = netip.AddrFromSlice(ipv4Layer.SrcIP)
			data = ipv4Layer.LayerPayload() // chop off the ip header
		} else if ipv6Layer.CanDecode().Contains(networkLayer) {
			if err := ipv6Layer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
				continue
			}
			if !udpLayer.CanDecode().Contains(ipv4Layer.NextLayerType()) {
				// Not UPD? Could be extensions...we don't expect any.
				continue
			}
			// Retrieve src from the decoded IP layers.
			srcIP, validSrc = netip.AddrFromSlice(ipv6Layer.SrcIP)
			data = ipv6Layer.LayerPayload() // chop off the ip header
		} else {
			continue
		}
		if !validSrc {
			// WTF?
			continue
		}
		if err := udpLayer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			continue
		}
		p.RawPacket = udpLayer.LayerPayload() // chop off the udp header. The rest is SCION.
		srcAddr := netip.AddrPortFrom(srcIP, uint16(udpLayer.SrcPort))

		// Demultiplex to a link. There is one connection per interface, so they are mostly shared
		// between links; including the internal link. The internal link catches all remote
		// addresses that no other link claims. That is what u.link is. Connections that are not
		// shared with the internal link do not have it as they should not accept packets from
		// unknown sources (but they might receive them: the ebpf filter only looks at port).
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
		l.receive(&srcAddr, p)
		p = pool.Get() // we need a fresh packet buffer now.
	}

	// We have to stop receiving. Return the unused packet to the pool to avoid creating
	// a memory leak (the process is not required to exit - e.g. in tests).
	pool.Put(p)
}

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
	log.Debug("Send", "connection", u.name)

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
