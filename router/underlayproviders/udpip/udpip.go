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

package udpip

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/slayers"
	underlayconn "github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/bfd"
)

// provider implements UnderlayProvider by making and returning Udp/Ip links.
//
// This is currently the only implementation. The goal of splitting out this code from the router
// is to enable other implementations. However, as a first step, we continue assuming that the
// batchConn is given to us and is a UDP socket and that, in the case of externalLink, it is bound.
type provider struct {
	mu                 sync.Mutex // Prevents race between adding connections and Start/Stop.
	batchSize          int        // TODO(multi_underlay): Should have an underlay-specific config.
	allLinks           map[netip.AddrPort]udpLink
	allConnections     []*udpConnection
	internalConnection *udpConnection // Because we share it w/ siblinglinks
	internalLink       *internalLink  // Because we share it's hashseed w/ siblinglinks
}

var (
	errShortPacket = errors.New("Packet is too short")
)

type udpLink interface {
	router.Link
	start(ctx context.Context, procQs []chan *router.Packet, pool chan *router.Packet)
	stop()
	hashSeed() uint32 // We copy the hashSeed from the internal connection to sibling connections.
	receive(size int, srcAddr *net.UDPAddr, pkt *router.Packet)
}

func init() {
	// Register ourselves as an underlay provider. The registration consists of a constructor, not
	// a provider object, because multiple router instances each must have their own underlay
	// provider. The provider is not re-entrant.
	router.AddUnderlay(newProvider)
}

// New instantiates a new instance of the provider for exclusive use by the caller.
func newProvider(batchSize int) router.UnderlayProvider {
	return &provider{
		batchSize: batchSize,
		allLinks:  make(map[netip.AddrPort]udpLink),
	}
}

func (u *provider) NumConnections() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.allLinks)
}

// The queues to be used by the receiver task are supplied at this point because they must be
// sized according to the number of connections that will be started.
func (u *provider) Start(
	ctx context.Context, pool chan *router.Packet, procQs []chan *router.Packet) {

	u.mu.Lock()
	if len(procQs) == 0 {
		// Pointless to run without any processor of incoming traffic
		return
	}
	connSnapShot := slices.Clone(u.allConnections)
	linkSnapShot := append(slices.Collect(maps.Values(u.allLinks)), u.internalLink)
	u.mu.Unlock()

	// Links MUST be started before connections. They need procQs and pool to process
	// incoming packets. Given that this is an internal mater, we don't pay the
	// price of checking at use time.
	for _, l := range linkSnapShot {
		l.start(ctx, procQs, pool)
	}
	for _, c := range connSnapShot {
		c.start(u.batchSize, pool)
	}
}

func (u *provider) Stop() {
	u.mu.Lock()
	connSnapShot := slices.Clone(u.allConnections)
	linkSnapShot := append(slices.Collect(maps.Values(u.allLinks)), u.internalLink)
	u.mu.Unlock()

	for _, c := range connSnapShot {
		c.stop()
	}
	for _, l := range linkSnapShot {
		l.stop()
	}
}

func (u *provider) Link(addr netip.AddrPort) router.Link {
	u.mu.Lock()
	defer u.mu.Unlock()

	// There is one link for every address. The internal Link catches all.
	l, found := u.allLinks[addr]
	if found {
		return l
	}
	return u.internalLink
}

// udpConnection is essentially a BatchConn with a sending queue. The rest is about logs and
// metrics. This allows UDP connections to be shared between links. Bundling link and
// connection together is possible and simpler for the code here, but leaks more refactoring changes
// in the main router code. Specifically, either:
//   - sibling links would each need an independent socket to the sibling router, which
//     the router cannot provide at the moment.
//   - the internal links and sibling links would be the same, which means the router needs to
//     special case the sibling links: which we want to remove from the main code.
type udpConnection struct {
	conn         router.BatchConn
	queue        chan *router.Packet
	metrics      router.InterfaceMetrics
	ifID         uint16 // TODO(multi_underlay): temorary (is 0 for sibling and internal links)
	name         string // for logs. It's more informative than ifID.
	running      atomic.Bool
	receiverDone chan struct{}
	senderDone   chan struct{}
	link         *externalLink              // Link that has exclusive use of this. Only ExternalLink.
	links        map[netip.AddrPort]udpLink // Links that share this connection
}

// start puts the connection in the running state. In that state, the connection can deliver
// incoming packets and ignores packets present on its input channel.
func (u *udpConnection) start(batchSize int, pool chan *router.Packet) {

	wasRunning := u.running.Swap(true)
	if wasRunning {
		return
	}

	// Receiver task
	go func() {
		defer log.HandlePanic()
		u.receive(batchSize, pool)
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
// stopped when this method returns.
func (u *udpConnection) stop() {
	wasRunning := u.running.Swap(false)

	if wasRunning {
		u.conn.Close() // Unblock receiver
		close(u.queue) // Unblock sender
		<-u.receiverDone
		<-u.senderDone
	}
}

func (u *udpConnection) receive(
	batchSize int, pool chan *router.Packet) {

	log.Debug("Receive", "connection", u.name)

	// A collection of socket messages, as the readBatch API expects them. We keep using the same
	// collection, call after call; only replacing the buffer.
	msgs := underlayconn.NewReadMessages(batchSize)

	// An array of corresponding packet references. Each corresponds to one msg.
	// The packet owns the buffer that we set in the matching msg, plus the metadata that we'll add.
	packets := make([]*router.Packet, batchSize)
	numReusable := 0 // unused buffers from previous loop

	for u.running.Load() {
		// collect packets.

		// Give a new buffer to the msgs elements that have been used in the previous loop.
		for i := 0; i < batchSize-numReusable; i++ {
			p := <-pool
			p.Reset()
			packets[i] = p
			msgs[i].Buffers[0] = p.RawPacket
		}

		// Fill the packets
		numPkts, err := u.conn.ReadBatch(msgs)
		numReusable = len(msgs) - numPkts
		if err != nil {
			log.Debug("Error while reading batch", "connection", u.name, "err", err)
			continue
		}
		for i, msg := range msgs[:numPkts] {

			// Update size; readBatch does not.
			size := msg.N
			pkt := packets[i]
			pkt.RawPacket = pkt.RawPacket[:size]

			// Find the right link. For unshared connections, it's easy: we know the link.
			// TODO(multi_underlay): this may justify creating multiple udpConnections
			// implementations?. For example, converting the srcAddr to a netip.AddrPort
			// is expensive; we could pass it to receive, but we wouldn't want to do it
			// for bound connections.
			if u.link != nil {
				u.link.receive(size, msg.Addr.(*net.UDPAddr), pkt)
				continue
			}

			// Ok then, find it by remote address. We have a map of *our* links, so it's short.
			srcAddr := msg.Addr.(*net.UDPAddr).AddrPort() // POSSIBLY EXPENSIVE CONVERSION
			l, found := u.links[srcAddr]
			if !found {
				// Anything else is the internal link.
				l = u.links[netip.AddrPort{}]
			}
			l.receive(size, msg.Addr.(*net.UDPAddr), pkt)
		}
	}

	// We have to stop receiving. Return the unsent packets to the pool to avoid creating
	// a memory leak (it is likely but not required that the process will exit).
	for _, pkt := range packets[batchSize-numReusable : batchSize] {
		pool <- pkt
	}
}

// TODO(multi_underlay): simplify this a bit by making it a method of udpConnection.
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

// TODO(jiceatscion): There is a big issue with metrics and ifID. If an underlay connection must be
// shared between links (for example, sibling links), then we don't have a specific ifID in the
// connection per se. It changes for each packet. As a result, in the shared case, either we account
// all metrics to whatever placeholder ifID we have (i.e. 0), or we have to use pkt.egress and
// lookup the metrics in the map for each packet. This is too expensive.
//
// Mitigations:
//   - use ifID even if it is 0 for sibling links - no worse than before, since sibling links were
//     already redirected to interface 0 (...until we have fully shared forwarders - like with an
//     XDP underlay impl).
//   - stage our own internal metrics map, sorted by ifID = pkt.egress, and batch update the
//     metrics... might not be much cheaper than the naive way.
//   - Use one fw queue per ifID in each connection... but then have to round-robin for fairness....
//     smaller batches?
//
// For now, we do the first option. Whether that is good enough is still TBD.

func (u *udpConnection) send(batchSize int, pool chan *router.Packet) {
	log.Debug("Send", "connection", u.name)

	// We use this somewhat like a ring buffer.
	pkts := make([]*router.Packet, batchSize)

	// We use this as a temporary buffer, but allocate it just once
	// to save on garbage handling.
	msgs := make(underlayconn.Messages, batchSize)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
	}

	queue := u.queue
	conn := u.conn
	metrics := u.metrics
	toWrite := 0

	for u.running.Load() {
		// Top-up our batch.
		toWrite += readUpTo(queue, batchSize-toWrite, toWrite == 0, pkts[toWrite:])

		// Turn the packets into underlay messages that WriteBatch can send.
		for i, p := range pkts[:toWrite] {
			msgs[i].Buffers[0] = p.RawPacket
			msgs[i].Addr = nil
			// If we're a bound connection we do not need to specify the address. In fact
			// we really should not as it can cause unnecessary route queries. If we're
			// an unbound connection, we *must* specify the address, of course.
			if u.link == nil {
				// TODO(multi_underlay): bug compatibility w/ test! We must pretend
				// that we're a bound connection when the sender says so (by not setting
				// the destination)... change the test.
				if len(p.RemoteAddr.IP) != 0 {
					msgs[i].Addr = p.RemoteAddr
				}
			}
		}

		written, _ := conn.WriteBatch(msgs[:toWrite], 0)
		if written < 0 {
			// WriteBatch returns -1 on error, we just consider this as
			// 0 packets written
			written = 0
		}
		router.UpdateOutputMetrics(metrics, pkts[:written])
		for _, p := range pkts[:written] {
			pool <- p
		}
		if written != toWrite {
			// Only one is dropped at this time. We'll retry the rest.
			sc := router.ClassOfSize(len(pkts[written].RawPacket))
			metrics[sc].DroppedPacketsInvalid.Inc()
			pool <- pkts[written]
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

// TODO(jiceatscion): use more inheritance between implementations?

type externalLink struct {
	egressQ    chan<- *router.Packet
	procQs     []chan *router.Packet
	metrics    router.InterfaceMetrics
	ifID       uint16
	bfdSession *bfd.Session
	pool       chan *router.Packet
	seed       uint32
}

// NewExternalLink returns an external link over the UdpIpUnderlay.
//
// TODO(multi_underlay): we get the connection ready-made and require it to be bound. So, we
// don't keep the remote address, but in the future, we will be making the connections, and
// the conn argument will be gone.
func (u *provider) NewExternalLink(
	conn router.BatchConn,
	qSize int,
	bfd *bfd.Session,
	remote netip.AddrPort,
	ifID uint16,
	metrics router.InterfaceMetrics,
) router.Link {

	u.mu.Lock()
	defer u.mu.Unlock()

	// Note: tests do create external links with identical (zero) addresses. For consistency
	// with siblingLinks, we silently dedupe the links. Such tests just need the ifID to map
	// to something. This has the potential to hide a missconfiguration in the router, though.
	if l, _ := u.allLinks[remote]; l != nil {
		return l
	}

	queue := make(chan *router.Packet, qSize)
	el := &externalLink{
		egressQ:    queue,
		metrics:    metrics,
		ifID:       ifID,
		bfdSession: bfd,
		seed:       makeHashSeed(),
	}
	c := &udpConnection{
		conn:         conn,
		queue:        queue,
		metrics:      metrics, // send() needs them :-(
		ifID:         ifID,
		name:         remote.String(),
		receiverDone: make(chan struct{}),
		senderDone:   make(chan struct{}),
		link:         el,
	}
	u.allConnections = append(u.allConnections, c)
	u.allLinks[remote] = el
	return el
}

func (l *externalLink) start(ctx context.Context, procQs []chan *router.Packet, pool chan *router.Packet) {
	// procQs and pool are never known before all configured links have been instantiated.  So we
	// get then only now. We didn't need it earlier since the connections have not been started yet.
	l.procQs = procQs
	l.pool = pool
	if l.bfdSession == nil {
		return
	}
	go func() {
		defer log.HandlePanic()
		if err := l.bfdSession.Run(ctx); err != nil && err != bfd.AlreadyRunning {
			log.Error("BFD session failed to start", "external interface", l.ifID, "err", err)
		}
	}()
}

func (l *externalLink) stop() {
	if l.bfdSession == nil {
		return
	}
	l.bfdSession.Close()
}

func (l *externalLink) hashSeed() uint32 {
	return l.seed
}

func (l *externalLink) Scope() router.LinkScope {
	return router.External
}

// This is called for packets pretending to be in transit. So, an external link always
// checks false.
func (l *externalLink) CheckPktSrc(_ *router.Packet) bool {
	return false
}

func (l *externalLink) IsUp() bool {
	return l.bfdSession == nil || l.bfdSession.IsUp()
}

func (l *externalLink) Send(p *router.Packet) bool {
	select {
	case l.egressQ <- p:
	default:
		return false
	}
	return true
}

func (l *externalLink) SendBlocking(p *router.Packet) {
	l.egressQ <- p
}

func (l *externalLink) receive(size int, srcAddr *net.UDPAddr, pkt *router.Packet) {
	metrics := l.metrics
	sc := router.ClassOfSize(size)
	metrics[sc].InputPacketsTotal.Inc()
	metrics[sc].InputBytesTotal.Add(float64(size))
	procID, err := computeProcID(pkt.RawPacket, len(l.procQs), l.seed)

	if err != nil {
		log.Debug("Error while computing procID", "err", err)
		l.pool <- pkt
		metrics[sc].DroppedPacketsInvalid.Inc()
		return
	}

	// TODO(multi_underlay): This is temporary. The only use of src addr for external links
	// is a useless check that should be removed.
	// router.UpdateNetAddrFromNetAddr(pkt.RemoteAddr, srcAddr)
	pkt.Ingress = l.ifID
	pkt.BfdSession = l.bfdSession
	select {
	case l.procQs[procID] <- pkt:
	default:
		l.pool <- pkt
		metrics[sc].DroppedPacketsBusyProcessor.Inc()
	}
}

type siblingLink struct {
	egressQ    chan<- *router.Packet
	procQs     []chan *router.Packet
	metrics    router.InterfaceMetrics
	bfdSession *bfd.Session
	remote     *net.UDPAddr
	pool       chan *router.Packet
	seed       uint32
}

// newSiblingLink returns a sibling link over the UdpIpUnderlay.
//
// TODO(multi_underlay): this can only be an improvement over internalLink if we have a bound
// batchConn with the sibling router. However, currently the caller doesn't have one to give us;
// the main code has so far been reusing the internal connection. So, that's what we do for now.
// As a result, we keep the remote address; as we need to supply it for every packet being sent
// (something we will get rid of eventually).
// In the future we will be making one connection per remote address and we might even be able
// to erase the separation between link and connection for this implementation. Side effect
// of moving the address:link map here: the router does not know if there is an existing link. As
// a result it has to give us a BFDSession in all cases and we might throw it away (there
// are no permanent resources attached to it). This could be fixed by moving some BFD related code
// in-here.
func (u *provider) NewSiblingLink(
	qSize int,
	bfd *bfd.Session,
	remote netip.AddrPort,
	metrics router.InterfaceMetrics,
) router.Link {

	u.mu.Lock()
	defer u.mu.Unlock()

	// We silently deduplicate sibling links, so the router doesn't need to be aware or keep track
	// of link sharing.
	if l, _ := u.allLinks[remote]; l != nil {
		return l
	}

	// All sibling links re-use the internal connection. This used to be a late binding (packets to
	// siblings would get routed through the internal interface at run-time). But now this binding
	// happens right now and it can't work if this is called before newInternalLink.
	c := u.internalConnection
	if c == nil {
		// TODO(multi_underlay):That doesn't actually happen.
		// It is only required until we stop sharing the internal connection.
		panic("newSiblingLink called before newInternalLink")
	}

	sl := &siblingLink{
		egressQ:    c.queue, // And therefore we do not use qsize for now.
		metrics:    metrics,
		bfdSession: bfd,
		remote:     net.UDPAddrFromAddrPort(remote),
		seed:       u.internalLink.hashSeed(), // per connection, but used only by link.
	}
	c.links[remote] = sl
	u.allLinks[remote] = sl
	return sl
}

func (l *siblingLink) start(ctx context.Context, procQs []chan *router.Packet, pool chan *router.Packet) {
	// procQs and pool are never known before all configured links have been instantiated.  So we
	// get then only now. We didn't need it earlier since the connections have not been started yet.
	l.procQs = procQs
	l.pool = pool
	if l.bfdSession == nil {
		return
	}
	go func() {
		defer log.HandlePanic()
		if err := l.bfdSession.Run(ctx); err != nil && err != bfd.AlreadyRunning {
			log.Error("BFD session failed to start", "remote address", l.remote, "err", err)
		}
	}()
}

func (l *siblingLink) stop() {
	if l.bfdSession == nil {
		return
	}
	l.bfdSession.Close()
}

func (l *siblingLink) hashSeed() uint32 {
	return l.seed
}

func (l *siblingLink) Scope() router.LinkScope {
	return router.Sibling
}

func (l *siblingLink) CheckPktSrc(pkt *router.Packet) bool {
	return bytes.Equal(pkt.RemoteAddr.IP, l.remote.IP)
}

func (l *siblingLink) IsUp() bool {
	return l.bfdSession == nil || l.bfdSession.IsUp()
}

func (l *siblingLink) Send(p *router.Packet) bool {
	// We use an unbound connection but we offer a connection-oriented service. So, we need to
	// supply the packet's destination address.
	router.UpdateNetAddrFromNetAddr(p.RemoteAddr, l.remote)
	select {
	case l.egressQ <- p:
	default:
		return false
	}
	return true
}

func (l *siblingLink) SendBlocking(p *router.Packet) {
	// We use an unbound connection but we offer a connection-oriented service. So, we need to
	// supply the packet's destination address.
	router.UpdateNetAddrFromNetAddr(p.RemoteAddr, l.remote)
	l.egressQ <- p
}

func (l *siblingLink) receive(size int, srcAddr *net.UDPAddr, pkt *router.Packet) {
	metrics := l.metrics
	sc := router.ClassOfSize(size)
	metrics[sc].InputPacketsTotal.Inc()
	metrics[sc].InputBytesTotal.Add(float64(size))

	procID, err := computeProcID(pkt.RawPacket, len(l.procQs), l.seed)

	if err != nil {
		log.Debug("Error while computing procID", "err", err)
		l.pool <- pkt
		metrics[sc].DroppedPacketsInvalid.Inc()
	}

	router.UpdateNetAddrFromNetAddr(pkt.RemoteAddr, srcAddr)
	pkt.Ingress = 0
	pkt.BfdSession = l.bfdSession
	select {
	case l.procQs[procID] <- pkt:
	default:
		l.pool <- pkt
		metrics[sc].DroppedPacketsBusyProcessor.Inc()
	}
}

type internalLink struct {
	egressQ chan *router.Packet
	metrics router.InterfaceMetrics
	procQs  []chan *router.Packet
	pool    chan *router.Packet
	seed    uint32
}

// NewInternalLink returns a internal link over the UdpIpUnderlay.
//
// TODO(multi_underlay): we get the connection ready made. In the future we will be making it
// and the conn argument will be gone.
func (u *provider) NewInternalLink(
	conn router.BatchConn, qSize int, metrics router.InterfaceMetrics) router.Link {

	u.mu.Lock()
	defer u.mu.Unlock()

	if u.internalLink != nil {
		// We don't want to support this and the router doesn't do it.
		panic("More than one internal link")
	}

	queue := make(chan *router.Packet, qSize)
	il := &internalLink{
		egressQ: queue,
		metrics: metrics,
		seed:    makeHashSeed(),
	}
	c := &udpConnection{
		conn:         conn,
		queue:        queue,
		metrics:      metrics, // send() needs them :-(
		name:         "internal",
		ifID:         0,
		receiverDone: make(chan struct{}),
		senderDone:   make(chan struct{}),
		links:        make(map[netip.AddrPort]udpLink),
	}
	c.links[netip.AddrPort{}] = il
	u.internalConnection = c
	u.allConnections = append(u.allConnections, c)
	u.internalLink = il
	return il
}

func (l *internalLink) start(ctx context.Context, procQs []chan *router.Packet, pool chan *router.Packet) {
	// procQs and pool are never known before all configured links have been instantiated. So we
	// get then only now. We didn't need it earlier since the connections have not been started yet.
	l.procQs = procQs
	l.pool = pool
}

func (l *internalLink) stop() {
}

func (l *internalLink) hashSeed() uint32 {
	return l.seed
}

func (l *internalLink) Scope() router.LinkScope {
	return router.Internal
}

// This is called for packets pretending to be in transit. So, an internal link always
// checks false.
func (l *internalLink) CheckPktSrc(_ *router.Packet) bool {
	return false
}

func (l *internalLink) IsUp() bool {
	return true
}

// The packet's destination is already in the packet's meta-data.
func (l *internalLink) Send(p *router.Packet) bool {
	select {
	case l.egressQ <- p:
	default:
		return false
	}
	return true
}

// The packet's destination is already in the packet's meta-data.
func (l *internalLink) SendBlocking(p *router.Packet) {
	l.egressQ <- p
}

func (l *internalLink) receive(size int, srcAddr *net.UDPAddr, pkt *router.Packet) {
	metrics := l.metrics
	sc := router.ClassOfSize(size)
	metrics[sc].InputPacketsTotal.Inc()
	metrics[sc].InputBytesTotal.Add(float64(size))
	procID, err := computeProcID(pkt.RawPacket, len(l.procQs), l.seed)
	if err != nil {
		log.Debug("Error while computing procID", "err", err)
		l.pool <- pkt
		metrics[sc].DroppedPacketsInvalid.Inc()
		return
	}

	// This is an unbound link. We must record the src address in case the packet
	// is turned around by SCMP.
	router.UpdateNetAddrFromNetAddr(pkt.RemoteAddr, srcAddr)
	pkt.Ingress = 0
	// No bfd session for internal links
	select {
	case l.procQs[procID] <- pkt:
	default:
		l.pool <- pkt
		metrics[sc].DroppedPacketsBusyProcessor.Inc()
	}
}

// TODO(multi_underlay): For bound connections we could make this cheaper.
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
