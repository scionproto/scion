// Copyright 2025 SCION Association
//
// SPDX-License-Identifier: Apache-2.0

package afpacketudpip

import (
	"crypto/rand"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/router"
)

// addrPort is like netip.AddrPort but with mutable (for us) fields. This saves an address copy.
type addrPort struct {
	ip   netip.Addr
	port uint16
}

// fourTuple aggregates src and dst addrPorts.
type fourTuple struct {
	src addrPort
	dst addrPort
}

// udpConnection is a TPacket connection with a sending queue and a demultiplexer. The rest is
// about logs and metrics. This allows UDP connections to be shared between links, which is the
// norm in this case; since a raw socket receives traffic for all ports.
type udpConnection struct {
	localMAC     net.HardwareAddr
	connFilters  udpConnFilters
	name         string                // For logs. It's more informative than ifID.
	ptpLinks     map[fourTuple]udpLink // Link map for specific remote addresses.
	intLinks     map[addrPort]udpLink  // Link map for unknown remote addresses.
	afp          *afpacket.TPacket
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
		u.afp.Close()  // Unblock receiver
		close(u.queue) // Unblock sender
		u.connFilters.Close()
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
	var targetIP netip.Addr
	var senderIP netip.Addr
	var rcptIP netip.Addr

	// Get the MACs out of the packet too; it's all just slices referring to it.
	// Reduce them to just 6 bytes while we are at it.
	if len(arp.SourceHwAddress) != 6 {
		return
	}
	senderMAC := [6]byte(arp.SourceHwAddress)

	// We don't care about duplicate address probes nor about loopback devices.
	if senderMAC == zeroMacAddr {
		return
	}
	// TODO(jiceatscion): ignore gratuitous reqs
	isReq := (arp.Operation == layers.ARPRequest)

	if isReq {
		targetIP = netip.AddrFrom4([4]byte(arp.DstProtAddress))
		senderIP = netip.AddrFrom4([4]byte(arp.SourceProtAddress))
		rcptIP = targetIP
	} else {
		targetIP = netip.AddrFrom4([4]byte(arp.SourceProtAddress))
		senderIP = targetIP
		rcptIP = netip.AddrFrom4([4]byte(arp.DstProtAddress))
	}

	// We have to pass all requests to all links. Sometimes the sender uses an IP address
	// that we don't know about (e.g. the traffic generator uses interfaces with a different
	// IP assigned - which the arp lib then uses to make requests).
	for _, l := range u.ptpLinks {
		l.handleNeighbor(isReq, targetIP, senderIP, rcptIP, senderMAC)
	}
	for _, l := range u.intLinks {
		l.handleNeighbor(isReq, targetIP, senderIP, rcptIP, senderMAC)
	}
}

// Handle NDP minimally.
// Terminology just as shitty as ARP; only different - Summary of the protocol:
//
// |                     Sollicitations   |   advertisements
// ---------------------------------------------------------------
// IP to be resolved:    TargetAddress    |   TargetAddress
// IP of pkt sender:     from IP header   |   TargetAddress
// MAC to be found:      -                |   OptTargetAddress
// MAC of pkt sender:    OptSourceAddress |   -
func (u *udpConnection) handleV6NDP(icmp6 *layers.ICMPv6, srcIP, dstIP netip.Addr) {
	data := icmp6.LayerPayload()
	var isReq bool
	var valid bool
	var targetIP netip.Addr
	var rcptIP netip.Addr
	var remoteMAC [6]byte

	switch icmp6.TypeCode.Type() {
	case layers.ICMPv6TypeNeighborSolicitation:
		var query layers.ICMPv6NeighborSolicitation
		if err := query.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			return
		}
		targetIP, valid = netip.AddrFromSlice(query.TargetAddress)
		if !valid {
			return
		}
		rcptIP = targetIP // Even if it arrived via mcast.
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
			return
		}
		targetIP, valid = netip.AddrFromSlice(response.TargetAddress)
		if !valid {
			return
		}
		rcptIP = dstIP
		for _, opt := range response.Options {
			if opt.Type == layers.ICMPv6OptTargetAddress {
				if len(opt.Data) != 6 {
					return
				}
				remoteMAC = [6]byte(opt.Data)
			}
		}
	default:
		return
	}
	// We don't care about duplicate address probes nor about loopback devices.
	if remoteMAC == zeroMacAddr {
		return
	}
	// We have to pass all requests to all links. Sometimes the sender uses an IP address
	// that we don't know about (e.g. the traffic generator uses interfaces with a different
	// IP assigned - which the arp lib then uses to make requests).
	for _, l := range u.ptpLinks {
		l.handleNeighbor(isReq, targetIP, srcIP, rcptIP, remoteMAC)
	}
	for _, l := range u.intLinks {
		l.handleNeighbor(isReq, targetIP, srcIP, rcptIP, remoteMAC)
	}
}

func (u *udpConnection) receive(pool router.PacketPool) {
	// Since we do not know the real size of the IP header, we have to plan on it being short; so
	// our payload doesn't encroach on the headroom space. If the header is longer, then we will
	// leave more headroom than needed. We don't even know if we're getting v4 or v6. Assume v4.
	minHeadRoom := ethLen + ipv4Len + udpLen

	// We'll reuse this one until we can deliver it. At which point, we fetch a fresh one.
	// pool.Reset is much cheaper than pool.Put/Get
	p := pool.Get()

	for u.running.Load() {
		var ethLayer layers.Ethernet
		var arpLayer layers.ARP
		var icmp6Layer layers.ICMPv6
		var ipv4Layer layers.IPv4
		var ipv6Layer layers.IPv6
		var udpLayer layers.UDP
		var srcDst fourTuple
		var srcIPBytes []byte
		var validIP bool

		// Since it may be recycled...
		pool.ResetPacket(p)

		data := p.WithHeader(minHeadRoom) // data now maps to where we dump the whole packet
		_, err := u.afp.ReadPacketDataTo(data)
		if err != nil {
			continue
		}

		// DissectAndShow(data, "Received") // Enabled only if debug logging.

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
			// Retrieve src & dst from the decoded IP layers.
			srcDst.src.ip, validIP = netip.AddrFromSlice(ipv4Layer.SrcIP)
			if !validIP {
				// WTF?
				continue
			}
			srcIPBytes = ipv4Layer.SrcIP
			srcDst.dst.ip, validIP = netip.AddrFromSlice(ipv4Layer.DstIP)
			if !validIP {
				// WTF?
				continue
			}
			data = ipv4Layer.LayerPayload() // chop off the ip header
		case layers.EthernetTypeIPv6:
			if err := ipv6Layer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
				continue
			}
			// Retrieve src from the decoded IP layers.
			srcDst.src.ip, validIP = netip.AddrFromSlice(ipv6Layer.SrcIP)
			if !validIP {
				// WTF?
				continue
			}
			srcIPBytes = ipv6Layer.DstIP
			srcDst.dst.ip, validIP = netip.AddrFromSlice(ipv6Layer.DstIP)
			if !validIP {
				// WTF?
				continue
			}
			data = ipv6Layer.LayerPayload() // chop off the ip header
			if ipv6Layer.NextHeader == layers.IPProtocolICMPv6 {
				if err := icmp6Layer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
					u.handleV6NDP(&icmp6Layer, srcDst.src.ip, srcDst.dst.ip) // We own the packet.
				}
				continue
			} else if ipv6Layer.NextHeader != layers.IPProtocolUDP {
				// Not UPD either? Could be extensions. We don't expect any.
				continue
			}
		case layers.EthernetTypeARP:
			if err := arpLayer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
				u.handleArp(&arpLayer) // We own the packet.
			}
			continue
		default:
			continue
		}
		if err := udpLayer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			continue
		}
		p.RawPacket = udpLayer.LayerPayload() // chop off the udp header. The rest is SCION.

		// Demultiplex to a link. There is one connection per interface, so they are mostly shared
		// between links; including the internal link. The internal link catches all remote
		// addresses that no other link claims.
		srcDst.src.port = uint16(udpLayer.SrcPort)
		srcDst.dst.port = uint16(udpLayer.DstPort)
		if l, found := u.ptpLinks[srcDst]; found {
			l.receive(p)
			p = pool.Get() // we need a fresh packet buffer now.
			continue
		}
		if l, found := u.intLinks[srcDst.dst]; found {
			setRemoteAddr(p, srcIPBytes, srcDst.src.port)
			l.receive(p)
			p = pool.Get() // we need a fresh packet buffer now.
			continue
		}
	}
	// We have to stop receiving. Return the unused packet to the pool to avoid creating
	// a leak (the process is not required to exit - e.g. in tests).
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
		router.UpdateOutputMetrics(metrics, pkts[:written])
		for _, p := range pkts[:written] {
			// DissectAndShow(p.RawPacket, "Successfully Output") // Enabled only if debug logging.
			pool.Put(p)
		}
		if written == 0 {
			// This happens IFF there is an error and zero packets were sent.
			// The first packet may have caused it, so, drop it. We'll retry the rest.
			sc := router.ClassOfSize(len(pkts[0].RawPacket))
			metrics[sc].DroppedPacketsInvalid.Inc() // Need other drop reason counter
			pool.Put(pkts[0])
			written = 1 // At least, not to-be-written any more.
		}
		if written != toWrite {
			// Shift the leftovers to the head of the buffers.
			toWrite -= written
			for i := 0; i < toWrite; i++ {
				pkts[i] = pkts[i+written]
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

func newUdpConnection(
	intf net.Interface,
	qSize int,
	connOpener ConnOpener,
	metrics *router.InterfaceMetrics,
) (*udpConnection, error) {
	queue := make(chan *router.Packet, qSize)
	afp, connFilters, err := connOpener.Open(intf.Index)
	if err != nil {
		return nil, err
	}
	hwAddr := intf.HardwareAddr

	// Catering to tests that use a local address (on the loopback interface) which has no mac
	// address assigned. In that case neighbor address resolution isn't needed and doesn't work.
	// The neighbors cache dumbs itself down accordingly.
	if len(hwAddr) == 0 || slices.Equal(hwAddr, net.HardwareAddr{0, 0, 0, 0, 0, 0}) {
		// num := rand.Uint32()
		// hwAddr = net.HardwareAddr{2, 0, 0, 0, 0, 0}
		// binary.BigEndian.PutUint32(hwAddr[2:], num)
		hwAddr = zeroMacAddr[:]
	}
	return &udpConnection{
		localMAC:     hwAddr,
		connFilters:  connFilters,
		name:         intf.Name,
		afp:          afp,
		queue:        queue,
		ptpLinks:     make(map[fourTuple]udpLink),
		intLinks:     make(map[addrPort]udpLink),
		metrics:      metrics,
		seed:         makeHashSeed(),
		receiverDone: make(chan struct{}),
		senderDone:   make(chan struct{}),
	}, nil
}
