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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/private/underlay/ebpf"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/bfd"
)

var (
	errResolveOnNonInternalLink = errors.New("unsupported address resolution on link not internal")
	errInvalidServiceAddress    = errors.New("invalid service address")
	errShortPacket              = errors.New("packet is too short")
	errDuplicateRemote          = errors.New("duplicate remote address")
)

// An interface to enable unit testing.
type ConnOpener interface {
	// Creates a connection as specified.
	Open(index int, localPort uint16) (*afpacket.TPacket, *ebpf.FilterHandle, error)
}

// The default ConnOpener for this underlay: opens a afpacket socket.
type uo struct{}

func (_ uo) Open(index int, localPort uint16) (*afpacket.TPacket, *ebpf.FilterHandle, error) {
	intf, err := net.InterfaceByIndex(index)
	if err != nil {
		return nil, nil, serrors.Wrap("finding interface", err)
	}
	// Note that we have to make the TPacket non-blocking eventhough we have nothing special to do
	// in the absence of traffic, because it needs to be drained of packets after adding the filter.
	// The draining, and only that, requires a non-blocking operation. We use a longish timeout
	// since the rest of the time we don't actually want to wake up.
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(intf.Name),
		afpacket.OptPollTimeout(200*time.Millisecond),
		// afpacket.OptFrameSize(intf.MTU), // Constrained. default is probably best
	)
	if err != nil {
		return nil, nil, serrors.Wrap("creating TPacket", err)
	}

	filter, err := ebpf.BpfPortFilter(index, handle, localPort)
	if err != nil {
		return nil, nil, serrors.Wrap("adding port filter", err)
	}

	// Drain
	for {
		_, _, err = handle.ZeroCopyReadPacketData()
		if err != nil {
			break
		}
	}
	return handle, filter, nil
}

// provider implements UnderlayProvider by making and returning Udp/Ip links.
//
// This is currently the only implementation. The goal of splitting out this code from the router
// is to enable other implementations.
type provider struct {
	mu                sync.Mutex // Prevents race between adding connections and Start/Stop.
	batchSize         int
	allLinks          map[netip.AddrPort]udpLink
	allConnections    map[int]*udpConnection // One per network interface
	connOpener        ConnOpener             // uo{}, except for unit tests
	svc               *router.Services[netip.AddrPort]
	receiveBufferSize int
	sendBufferSize    int
	dispatchStart     uint16
	dispatchEnd       uint16
	dispatchRedirect  uint16
}

type udpLink interface {
	router.Link
	start(ctx context.Context, procQs []chan *router.Packet, pool router.PacketPool)
	stop()
	receive(srcAddr *netip.AddrPort, p *router.Packet)
}

func init() {
	// Register ourselves as an underlay provider. The registration consists of a factory, not
	// a provider object, because multiple router instances each must have their own underlay
	// provider. The provider is not re-entrant.

	// We add ourselves as an implementation of the "udpip" underlay. The two udpip underlays
	// are interchangeable. Only this one should perform better but exists only for Linux.
	// The priorities cause the router to chose this one over the other when both are available.
	router.AddUnderlay("udpip", providerFactory{})
}

// Implement router.ProviderFactory
type providerFactory struct{}

// New instantiates a new instance of the provider for exclusive use by the caller.
// TODO(multi_underlay): batchSize should be an underlay-specific config.
func (providerFactory) New(
	batchSize int,
	receiveBufferSize int,
	sendBufferSize int,
) router.UnderlayProvider {
	return &provider{
		batchSize:         batchSize,
		allLinks:          make(map[netip.AddrPort]udpLink),
		allConnections:    make(map[int]*udpConnection),
		connOpener:        uo{},
		svc:               router.NewServices[netip.AddrPort](),
		receiveBufferSize: receiveBufferSize,
		sendBufferSize:    sendBufferSize,
	}
}

func (providerFactory) Priority() int {
	return 2 // Until we know this works, make ourselves scarce
}

// SetConnOpener installs the given opener. opener must be an implementation of ConnOpener or
// panic will ensue. Only for use in unit tests.
func (u *provider) SetConnOpener(opener any) {
	u.connOpener = opener.(ConnOpener)
}

func (u *provider) NumConnections() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.allLinks)
}

func (u *provider) Headroom() int {

	// We advise of enough headroom for ethernet + max(ip) + udp headers on outgoing packets (we do
	// not need to add extensions and do not use options). On receipt, we cannot predict if the IP
	// header is v4 or v6 or has options or extentions. We align the packet with the assumtion that
	// it is v4 with no options. As a result, the payload never starts earlier than planned. This is
	// needed to ensure that the headroom we leave is never less than the worst case requirement
	// across all underlays.

	return 14 + 40 + 8 // ethernet + basic ipv6 + udp
}

func (u *provider) SetDispatchPorts(start, end, redirect uint16) {
	u.dispatchStart = start
	u.dispatchEnd = end
	u.dispatchRedirect = redirect
}

// AddSvc adds the address for the given service.
func (u *provider) AddSvc(svc addr.SVC, host addr.Host, port uint16) error {
	// We pre-resolve the addresses, which is trivial for this underlay.
	addr := netip.AddrPortFrom(host.IP(), port)
	if !addr.IsValid() {
		return errInvalidServiceAddress
	}
	u.svc.AddSvc(svc, addr)
	return nil
}

// DelSvc deletes the address for the given service.
func (u *provider) DelSvc(svc addr.SVC, host addr.Host, port uint16) error {
	addr := netip.AddrPortFrom(host.IP(), port)
	if !addr.IsValid() {
		return errInvalidServiceAddress
	}
	u.svc.DelSvc(svc, addr)
	return nil
}

// The queues to be used by the receiver task are supplied at this point because they must be
// sized according to the number of connections that will be started.
func (u *provider) Start(
	ctx context.Context, pool router.PacketPool, procQs []chan *router.Packet,
) {
	u.mu.Lock()
	if len(procQs) == 0 {
		// Pointless to run without any processor of incoming traffic
		return
	}
	connSnapshot := slices.Collect(maps.Values(u.allConnections))
	linkSnapshot := slices.Collect(maps.Values(u.allLinks))
	u.mu.Unlock()

	// Links MUST be started before connections. Given that this is an internal mater, we don't pay
	// the price of checking at use time.
	for _, l := range linkSnapshot {
		l.start(ctx, procQs, pool)
	}
	for _, c := range connSnapshot {
		c.start(u.batchSize, pool)
	}
}

func (u *provider) Stop() {
	u.mu.Lock()
	connSnapshot := slices.Collect(maps.Values(u.allConnections))
	linkSnapshot := slices.Collect(maps.Values(u.allLinks))
	u.mu.Unlock()

	for _, c := range connSnapshot {
		c.stop()
	}
	for _, l := range linkSnapshot {
		l.stop()
	}
}

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

// getUdpConnection returns the appropriate udpConnection; creating it if it doesn't exist yet.
func (u *provider) getUdpConnection(
	qSize int, local *netip.AddrPort,
	metrics *router.InterfaceMetrics,
) (*udpConnection, error) {

	// TODO(jiceatscion): We don't really need to go through every interface every time.
	interfaces, _ := net.Interfaces()
	for _, intf := range interfaces {
		if addrs, err := intf.Addrs(); err == nil {
			for _, addr := range addrs {
				// net.Addr is very generic. We have to take a guess (educated by reading the code)
				// at what the underlying type is to make our comparison.
				ipNet, ok := addr.(*net.IPNet)
				if ok {
					if ipNet.IP.String() == local.Addr().String() {
						c := u.allConnections[intf.Index]
						if c != nil {
							return c, nil
						}
						queue := make(chan *router.Packet, qSize)
						afp, filter, err := u.connOpener.Open(intf.Index, local.Port())
						if err != nil {
							return nil, err
						}
						c = &udpConnection{
							name:         intf.Name,
							afp:          afp,
							filter:       filter,
							queue:        queue,
							links:        make(map[netip.AddrPort]udpLink),
							metrics:      metrics,
							seed:         makeHashSeed(),
							receiverDone: make(chan struct{}),
							senderDone:   make(chan struct{}),
						}
						u.allConnections[intf.Index] = c
						return c, nil
					}
				}
			}
		}
	}

	return nil, errors.New("No interface with the requested address")
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
	// As of this writting we do not expect extensions, so the actual headers should
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

// ptpLink is a point-to-point link. All links share a single raw socket per NIC. However
// point to point links are dedicated to a single src/dst pair.
type ptpLink struct {
	procQs     []chan *router.Packet
	header     []byte
	name       string // For logs
	egressQ    chan<- *router.Packet
	metrics    *router.InterfaceMetrics
	pool       router.PacketPool
	bfdSession *bfd.Session
	scope      router.LinkScope
	seed       uint32
	ifID       uint16 // 0 for sibling links
	is4        bool
}

// Expensive. Call only to make a few prefab headers.
func (l *ptpLink) packHeader(src, dst *netip.AddrPort) {

	sb := gopacket.NewSerializeBuffer()
	ethernet := layers.Ethernet{
		// FIXME! We must get those from the interface and from ARP!
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x1, 0x1},
		DstMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x2, 0x2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(src.Port()),
		DstPort: layers.UDPPort(dst.Port()),
	}

	l.is4 = src.Addr().Is4()

	if l.is4 {

		ip := layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			SrcIP:    src.Addr().AsSlice(),
			DstIP:    dst.Addr().AsSlice(),
			Protocol: layers.IPProtocolUDP,
			// Flags:    layers.IPv4DontFragment, // Sure about that?
		}
		_ = udp.SetNetworkLayerForChecksum(&ip)
		err := gopacket.SerializeLayers(sb, seropts, &ethernet, &ip, &udp)
		if err != nil {
			// The only possible reason for this is in the few lines above.
			panic("Cannot serialize static header")
		}

		// We have to truncate the result; gopacket is scared of generating a packet shorter than the
		// ethernet minimum.
		l.header = sb.Bytes()[:42]
		return
	}
	ip := layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolUDP,
		HopLimit:   64,
		SrcIP:      src.Addr().AsSlice(),
		DstIP:      dst.Addr().AsSlice(),
	}
	_ = udp.SetNetworkLayerForChecksum(&ip)
	err := gopacket.SerializeLayers(sb, seropts, &ethernet, &ip, &udp)
	if err != nil {
		// The only possible reason for this is in the few lines above.
		panic("Cannot serialize static header")
	}

	// We have to truncate the result; gopacket is scared of generating a packet shorter than the
	// ethernet minimum.
	l.header = sb.Bytes()[:62]
	return
}

// FIXME: can do cleaner and more legible... and maybe faster.
func (l *ptpLink) addHeader(p *router.Packet) {
	payloadLen := len(p.RawPacket)
	p.RawPacket = p.WithHeader(len(l.header))
	copy(p.RawPacket, l.header)

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
	}

	// Fix the IPv6 payload length field (udp plus the scion stuff)
	binary.BigEndian.PutUint16(p.RawPacket[14+4:], uint16(payloadLen)+8)

	// Update UDP length
	binary.BigEndian.PutUint16(p.RawPacket[14+40+4:], uint16(payloadLen)+8)

	// For IPV6 we must compute the UDP checksum.
	// In theory we could dispense with it as we're a tunneling protocol; however all the plain
	// udp underlay implementations would drop the packets.
	protoAsBE32bit := []byte{0, 0, 0, 17}
	csum := gopacket.ComputeChecksum(p.RawPacket[14+8:14+40], 0)        // src+dst
	csum = gopacket.ComputeChecksum(p.RawPacket[14+40+4:14+40+6], csum) // UDP length
	csum = gopacket.ComputeChecksum(protoAsBE32bit, csum)               // 3bytes of 0 plus UDP proto num
	binary.BigEndian.PutUint16(p.RawPacket[14+40+18:], gopacket.FoldChecksum(csum))
}

// NewExternalLink returns an external link over the UDP/IP underlay. It is implemented with a
// ptpLink and has a specific ifID.
func (u *provider) NewExternalLink(
	qSize int,
	bfd *bfd.Session,
	local string,
	remote string,
	ifID uint16,
	metrics *router.InterfaceMetrics,
) (router.Link, error) {
	localAddr, err := conn.ResolveAddrPortOrPort(local)
	if err != nil {
		return nil, serrors.Wrap("resolving local address", err)
	}
	remoteAddr, err := conn.ResolveAddrPort(remote)
	if err != nil {
		return nil, serrors.Wrap("resolving remote address", err)
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	// Duplicate external links are not supported. That they happen at all would denote a serious
	// configuration error.
	if l := u.allLinks[remoteAddr]; l != nil {
		return nil, serrors.Join(errDuplicateRemote, nil, "addr", remote)
	}
	c, err := u.getUdpConnection(qSize, &localAddr, metrics)
	if err != nil {
		return nil, err
	}

	el := &ptpLink{
		name:       remoteAddr.String(),
		egressQ:    c.queue,
		metrics:    metrics,
		bfdSession: bfd,
		seed:       c.seed,
		ifID:       ifID,
		scope:      router.External,
	}
	el.packHeader(&localAddr, &remoteAddr)
	c.links[remoteAddr] = el
	u.allLinks[remoteAddr] = el
	return el, nil
}

// NewSiblingLink returns an external link over the UDP/IP underlay. It is implemented with a
// ptpLink and has the unspecified ifID: 0.
//
// We de-duplicate sibling links. The router gives us a BFDSession in all cases and we might throw
// it away (there are no persistent resources attached to it). This could be fixed by moving some
// BFD related code in-here.
func (u *provider) NewSiblingLink(
	qSize int,
	bfd *bfd.Session,
	local string,
	remote string,
	metrics *router.InterfaceMetrics,
) (router.Link, error) {
	localAddr, err := conn.ResolveAddrPortOrPort(local)
	if err != nil {
		return nil, serrors.Wrap("resolving local address", err)
	}
	remoteAddr, err := conn.ResolveAddrPort(remote)
	if err != nil {
		return nil, serrors.Wrap("resolving remote address", err)
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	// We silently deduplicate sibling links, so the router doesn't need to be aware or keep track
	// of link sharing.
	if l := u.allLinks[remoteAddr]; l != nil {
		return l, nil
	}
	c, err := u.getUdpConnection(qSize, &localAddr, metrics)
	if err != nil {
		return nil, err
	}
	el := &ptpLink{
		name:       remoteAddr.String(),
		egressQ:    c.queue,
		metrics:    metrics,
		bfdSession: bfd,
		seed:       c.seed,
		ifID:       0,
		scope:      router.Sibling,
	}
	el.packHeader(&localAddr, &remoteAddr)
	c.links[remoteAddr] = el
	u.allLinks[remoteAddr] = el
	return el, nil
}

func (l *ptpLink) start(
	ctx context.Context,
	procQs []chan *router.Packet,
	pool router.PacketPool,
) {
	// procQs and pool are never known before all configured links have been instantiated.  So we
	// get them only now. We didn't need it earlier since the connections have not been started yet.
	l.procQs = procQs
	l.pool = pool
	if l.bfdSession == nil {
		return
	}
	go func() {
		defer log.HandlePanic()
		if err := l.bfdSession.Run(ctx); err != nil && !errors.Is(err, bfd.ErrAlreadyRunning) {
			log.Error("BFD session failed to start", "remote address", l.name, "err", err)
		}
	}()
}

func (l *ptpLink) stop() {
	if l.bfdSession == nil {
		return
	}
	l.bfdSession.Close()
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
	return errResolveOnNonInternalLink
}

func (l *ptpLink) Send(p *router.Packet) bool {
	// We do not have an underlying connection. Instead we supply the entire underlay header. We
	// have it mostly canned and paste it in front of the packet.
	l.addHeader(p)

	select {
	case l.egressQ <- p:
	default:
		return false
	}
	return true
}

func (l *ptpLink) SendBlocking(p *router.Packet) {
	// Same as Send(). We must supply the header.
	l.addHeader(p)

	l.egressQ <- p
}

// receive delivers an incoming packet to the appropriate processing queue.
func (l *ptpLink) receive(srcAddr *netip.AddrPort, p *router.Packet) {
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

type internalLink struct {
	procQs           []chan *router.Packet
	header           []byte
	egressQ          chan *router.Packet
	metrics          *router.InterfaceMetrics
	pool             router.PacketPool
	svc              *router.Services[netip.AddrPort]
	seed             uint32
	dispatchStart    uint16
	dispatchEnd      uint16
	dispatchRedirect uint16
	is4              bool
}

// Expensive. Call only to make a few prefab headers.
func (l *internalLink) packHeader(src *netip.AddrPort) {

	sb := gopacket.NewSerializeBuffer()
	ethernet := layers.Ethernet{
		// FIXME! We must get those from the interface and from ARP!
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x1, 0x1},
		DstMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x2, 0x2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(src.Port()),
	}
	l.is4 = src.Addr().Is4()

	if l.is4 {
		ip := layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			SrcIP:    src.Addr().AsSlice(),
			DstIP:    netip.IPv4Unspecified().AsSlice(),
			Protocol: layers.IPProtocolUDP,
			// Flags:    layers.IPv4DontFragment, // Sure about that?
		}
		_ = udp.SetNetworkLayerForChecksum(&ip)
		err := gopacket.SerializeLayers(sb, seropts, &ethernet, &ip, &udp)
		if err != nil {
			// The only possible reason for this is in the few lines above.
			panic("Cannot serialize static header")
		}

		// We have to truncate the result; gopacket is scared of generating a packet shorter than the
		// ethernet minimum.
		l.header = sb.Bytes()[:42]
		return
	}

	ip := layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolUDP,
		HopLimit:   64,
		SrcIP:      src.Addr().AsSlice(),
		DstIP:      netip.IPv6Unspecified().AsSlice(),
	}
	_ = udp.SetNetworkLayerForChecksum(&ip)
	err := gopacket.SerializeLayers(sb, seropts, &ethernet, &ip, &udp)
	if err != nil {
		// The only possible reason for this is in the few lines above.
		panic("Cannot serialize static header")
	}

	// We have to truncate the result; gopacket is scared of generating a packet shorter than the
	// ethernet minimum.
	l.header = sb.Bytes()[:62]
}

// FIXME: can do cleaner and more legible... and maybe faster.
func (l *internalLink) addHeader(p *router.Packet, dst *netip.AddrPort) {
	payloadLen := len(p.RawPacket)
	p.RawPacket = p.WithHeader(len(l.header))
	copy(p.RawPacket, l.header)

	// Inject dest
	copy(p.RawPacket, net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x2, 0x2})
	copy(p.RawPacket[14+16:], dst.Addr().AsSlice()) // Can do cheaper?
	binary.BigEndian.PutUint16(p.RawPacket[14+20+2:], dst.Port())

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
	}

	// Fix the IPv6 payload length field (udp plus the scion stuff)
	binary.BigEndian.PutUint16(p.RawPacket[14+4:], uint16(payloadLen)+8)

	// Update UDP length
	binary.BigEndian.PutUint16(p.RawPacket[14+40+4:], uint16(payloadLen)+8)

	// For IPV6 we must compute the UDP checksum.
	// In theory we could dispense with it as we're a tunneling protocol; however all the plain
	// udp underlay implementations would drop the packets.
	protoAsBE32bit := []byte{0, 0, 0, 17}
	csum := gopacket.ComputeChecksum(p.RawPacket[14+8:14+40], 0)        // src+dst
	csum = gopacket.ComputeChecksum(p.RawPacket[14+40+4:14+40+6], csum) // UDP length
	csum = gopacket.ComputeChecksum(protoAsBE32bit, csum)               // 3bytes of 0 plus UDP proto num
	binary.BigEndian.PutUint16(p.RawPacket[14+40+18:], gopacket.FoldChecksum(csum))
}

// NewInternalLink returns a internal link over the UdpIpUnderlay.
//
// TODO(multi_underlay): We still go with the assumption that internal links are always
// udpip, so we don't expect a string here. That should change.
func (u *provider) NewInternalLink(
	local string, qSize int, metrics *router.InterfaceMetrics,
) (router.Link, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	localAddr, err := conn.ResolveAddrPort(local)
	if err != nil {
		return nil, serrors.Wrap("resolving local address", err)
	}
	c, err := u.getUdpConnection(qSize, &localAddr, metrics)
	if err != nil {
		return nil, err
	}

	// We prepare an incomplete header; it is still faster to patch it than recreate it
	// from scratch for every packet.
	il := &internalLink{
		egressQ:          c.queue,
		metrics:          metrics,
		svc:              u.svc,
		seed:             c.seed,
		dispatchStart:    u.dispatchStart,
		dispatchEnd:      u.dispatchEnd,
		dispatchRedirect: u.dispatchRedirect,
	}
	il.packHeader(&localAddr)
	c.link = il
	u.allLinks[netip.AddrPort{}] = il
	return il, nil
}

func (l *internalLink) start(
	ctx context.Context,
	procQs []chan *router.Packet,
	pool router.PacketPool,
) {
	// procQs and pool are never known before all configured links have been instantiated. So we
	// get them only now. We didn't need it earlier since the connections have not been started yet.
	l.procQs = procQs
	l.pool = pool
}

func (l *internalLink) stop() {
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
	if port < l.dispatchStart && port > l.dispatchEnd {
		port = l.dispatchRedirect
	}

	// Packets that get here must have come from an external or a sibling link; neither of which
	// attach a RemoteAddr to the packet (besides; it could be a different type). So, RemoteAddr is
	// not generally usable. We must allocate a new object. The precautions needed to pool them cost
	// more than the pool saves (verified experimentally).
	addrPort := netip.AddrPortFrom(dstAddr, port)
	p.RemoteAddr = unsafe.Pointer(&addrPort)

	return nil
}

func (l *internalLink) Send(p *router.Packet) bool {
	// TODO(jiceatscion): The packet's destination is in the packet's meta-data; it was put there by
	// Resolve() We need to craft a header in front of the packet.  May be resolve could do that,
	// instead of just storing the destination in the packet structure. That would save us the
	// allocation of address but requires some more changes to the dataplane code structure.
	l.addHeader(p, (*netip.AddrPort)(p.RemoteAddr))
	select {
	case l.egressQ <- p:
	default:
		return false
	}
	return true
}

func (l *internalLink) SendBlocking(p *router.Packet) {
	// Likewise: p.remoteAddress -> header.
	l.addHeader(p, (*netip.AddrPort)(p.RemoteAddr))
	l.egressQ <- p
}

// receive delivers an incoming packet to the appropriate processing queue.
// Because this link is not associated with a specific remote address, the src
// address of the packet is recorded in the packet structure. This may be used
// as the destination if SCMP responds.
func (l *internalLink) receive(srcAddr *netip.AddrPort, p *router.Packet) {
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
	// This is an unconnected link. We must record the src address in case the packet is turned
	// around by SCMP.

	// One of p.RemoteAddr or srcAddr becomes garbage. Keeping srcAddr doesn't require copying.
	p.RemoteAddr = unsafe.Pointer(srcAddr)

	select {
	case l.procQs[procID] <- p:
	default:
		l.pool.Put(p)
		metrics[sc].DroppedPacketsBusyProcessor.Inc()
	}
}

// Technically, this is a layering violation. We're peeking into the SCION packet for the
// flowID...oh well.
func computeProcID(data []byte, numProcRoutines int, hashSeed uint32) (uint32, error) {
	if len(data) < slayers.CmnHdrLen {
		return 0, errShortPacket
	}
	dstHostAddrLen := slayers.AddrType(data[9] >> 4 & 0xf).Length()
	srcHostAddrLen := slayers.AddrType(data[9] & 0xf).Length()
	addrHdrLen := 2*addr.IABytes + srcHostAddrLen + dstHostAddrLen
	if len(data) < slayers.CmnHdrLen+addrHdrLen {
		return 0, errShortPacket
	}

	s := hashSeed

	// inject the flowID
	s = hashFNV1a(s, data[1]&0xF) // The left 4 bits aren't part of the flowID.
	for _, c := range data[2:4] {
		s = hashFNV1a(s, c)
	}

	// Inject the src/dst addresses
	for _, c := range data[slayers.CmnHdrLen : slayers.CmnHdrLen+addrHdrLen] {
		s = hashFNV1a(s, c)
	}

	return s % uint32(numProcRoutines), nil
}
