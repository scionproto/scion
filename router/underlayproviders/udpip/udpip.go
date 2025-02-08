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
	"context"
	"crypto/rand"
	"errors"
	"maps"
	"net"
	"net/netip"
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
	mu             sync.Mutex // Prevents race between adding connections and Start/Stop.
	batchSize      int        // TODO(multi_underlay): Should have an underlay-specific config.
	allLinks       map[netip.AddrPort]udpLink
	allConnections map[netip.AddrPort]*udpConnection
}

var (
	errShortPacket = errors.New("Packet is too short")
)

type udpLink interface {
	router.Link
	start(ctx context.Context)
	stop()
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
		batchSize:      batchSize,
		allLinks:       make(map[netip.AddrPort]udpLink),
		allConnections: make(map[netip.AddrPort]*udpConnection),
	}
}

func (u *provider) NumConnections() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.allLinks)
}

// The queues to be used by the receiver task are supplied at this point because they must be
// sized according to the number of connections that will be started.
func (u *provider) Start(ctx context.Context, pool chan *router.Packet, procQs []chan *router.Packet) {
	u.mu.Lock()
	connSnapShot := maps.Clone(u.allConnections)
	linkSnapShot := maps.Clone(u.allLinks)
	u.mu.Unlock()

	for _, c := range connSnapShot {
		c.start(u.batchSize, pool, procQs)
	}

	for _, l := range linkSnapShot {
		l.start(ctx)
	}
}

func (u *provider) Stop() {
	u.mu.Lock()
	connSnapShot := maps.Clone(u.allConnections)
	linkSnapShot := maps.Clone(u.allLinks)
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
	return u.allLinks[netip.AddrPort{}]
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
	ifID         uint16 // TODO(multi_underlay): temorary (is 0 for sibling and internal links)
	name         string // for logs. It's more informative than ifID.
	running      atomic.Bool
	metrics      router.InterfaceMetrics
	receiverDone chan struct{}
	senderDone   chan struct{}
}

// start puts the connection in the running state. In that state, the connection can deliver
// incoming packets and ignores packets present on its input channel.
func (u *udpConnection) start(
	batchSize int, pool chan *router.Packet, procQs []chan *router.Packet) {

	wasRunning := u.running.Swap(true)
	if wasRunning || len(procQs) == 0 { // Pointless to receive without any processor.
		return
	}

	// Receiver
	go func() {
		defer log.HandlePanic()
		u.receiver(batchSize, pool, procQs)
		close(u.receiverDone)

	}()

	// Forwarder
	go func() {
		defer log.HandlePanic()
		u.sender(batchSize, pool)
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

func (u *udpConnection) receiver(
	batchSize int, pool chan *router.Packet, procQs []chan *router.Packet) {

	log.Debug("Run receiver", "connection", u.name)

	// Each receiver (therefore each input interface) has a unique random seed for the procID hash
	// function.
	hashSeed := fnv1aOffset32
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		panic("Error while generating random value")
	}
	for _, c := range randomBytes {
		hashSeed = hashFNV1a(hashSeed, c)
	}

	// A collection of socket messages, as the readBatch API expects them. We keep using the same
	// collection, call after call; only replacing the buffer.
	msgs := underlayconn.NewReadMessages(batchSize)

	// An array of corresponding packet references. Each corresponds to one msg.
	// The packet owns the buffer that we set in the matching msg, plus the metadata that we'll add.
	packets := make([]*router.Packet, batchSize)

	numReusable := 0 // unused buffers from previous loop
	ifID := u.ifID
	metrics := u.metrics

	enqueueForProcessing := func(size int, srcAddr *net.UDPAddr, pkt *router.Packet) {
		sc := router.ClassOfSize(size)
		metrics[sc].InputPacketsTotal.Inc()
		metrics[sc].InputBytesTotal.Add(float64(size))

		procID, err := computeProcID(pkt.RawPacket, len(procQs), hashSeed)
		if err != nil {
			log.Debug("Error while computing procID", "err", err)
			pool <- pkt
			metrics[sc].DroppedPacketsInvalid.Inc()
			return
		}

		pkt.RawPacket = pkt.RawPacket[:size] // Update size; readBatch does not.

		// TODO(multi_underlay): We should begin with finding the link and get the ifID
		// from there.
		pkt.Ingress = ifID
		pkt.SrcAddr = srcAddr
		select {
		case procQs[procID] <- pkt:
		default:
			pool <- pkt
			metrics[sc].DroppedPacketsBusyProcessor.Inc()
		}
	}

	conn := u.conn
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
		numPkts, err := conn.ReadBatch(msgs)
		numReusable = len(msgs) - numPkts
		if err != nil {
			log.Debug("Error while reading batch", "interfaceID", ifID, "err", err)
			continue
		}
		for i, msg := range msgs[:numPkts] {
			enqueueForProcessing(msg.N, msg.Addr.(*net.UDPAddr), packets[i])
		}
	}
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

func (u *udpConnection) sender(batchSize int, pool chan *router.Packet) {
	log.Debug("Run forwarder", "connection", u.name)

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
			if len(p.DstAddr.IP) != 0 {
				msgs[i].Addr = p.DstAddr
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

// TODO(jiceatscion): use more inheritance between implementations?

type externalLink struct {
	queue      chan<- *router.Packet
	ifID       uint16
	bfdSession router.BFDSession
	remote     netip.AddrPort
}

// NewExternalLink returns an external link over the UdpIpUnderlay.
//
// TODO(multi_underlay): we get the connection ready-made and require it to be bound. So, we
// don't keep the remote address, but in the future, we will be making the connections, and
// the conn argument will be gone.
func (u *provider) NewExternalLink(
	conn router.BatchConn,
	qSize int,
	bfd router.BFDSession,
	remote netip.AddrPort,
	ifID uint16,
	metrics router.InterfaceMetrics,
) router.Link {

	queue := make(chan *router.Packet, qSize)
	c := &udpConnection{
		conn:         conn,
		queue:        queue,
		ifID:         ifID,
		name:         remote.String(),
		metrics:      metrics,
		receiverDone: make(chan struct{}),
		senderDone:   make(chan struct{}),
	}
	l := &externalLink{
		bfdSession: bfd,
		queue:      queue,
		ifID:       ifID,
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	u.allConnections[remote] = c
	u.allLinks[remote] = l
	return l
}

func (l *externalLink) start(ctx context.Context) {
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

func (l *externalLink) stop() {
	if l.bfdSession == nil {
		return
	}
	l.bfdSession.Close()
}

func (l *externalLink) Scope() router.LinkScope {
	return router.External
}

func (l *externalLink) IsUp() bool {
	return l.bfdSession == nil || l.bfdSession.IsUp()
}

func (l *externalLink) BFDSession() router.BFDSession {
	return l.bfdSession
}

func (l *externalLink) IfID() uint16 {
	return l.ifID
}

func (l *externalLink) Remote() netip.AddrPort {
	return l.remote
}

func (l *externalLink) Send(p *router.Packet) bool {
	select {
	case l.queue <- p:
	default:
		return false
	}
	return true
}

func (l *externalLink) SendBlocking(p *router.Packet) {
	l.queue <- p
}

type siblingLink struct {
	queue      chan<- *router.Packet
	bfdSession router.BFDSession
	remote     netip.AddrPort
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
// are no permanent resources attached to it). This will be fixed by moving some BFD related code
// in-here.
func (u *provider) NewSiblingLink(
	qSize int, bfd router.BFDSession,
	remote netip.AddrPort,
	metrics router.InterfaceMetrics,
) router.Link {

	u.mu.Lock()
	defer u.mu.Unlock()

	// There is exactly one sibling link per sibling router address.
	l, exists := u.allLinks[remote]
	if exists {
		return l.(*siblingLink)
	}

	// All sibling links re-use the internal connection. This used to be a late binding (packets to
	// siblings would get routed through the internal interface at run-time). But now this binding
	// happens right now and it can't work if this is called before newInternalLink.
	c, exists := u.allConnections[netip.AddrPort{}]
	if !exists {
		// TODO(multi_underlay):That doesn't actually happen.
		// It is only required until we stop sharing the internal connection.
		panic("newSiblingLink called before newInternalLink")
	}

	s := &siblingLink{
		queue:      c.queue, // And therefor we do not use qsize for now.
		bfdSession: bfd,
		remote:     remote,
	}
	u.allLinks[remote] = s
	return s
}

func (l *siblingLink) start(ctx context.Context) {
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

func (l *siblingLink) Scope() router.LinkScope {
	return router.Sibling
}

func (l *siblingLink) IsUp() bool {
	return l.bfdSession == nil || l.bfdSession.IsUp()
}

func (l *siblingLink) BFDSession() router.BFDSession {
	return l.bfdSession
}

func (l *siblingLink) IfID() uint16 {
	return 0
}

func (l *siblingLink) Remote() netip.AddrPort {
	return l.remote
}

func (l *siblingLink) Send(p *router.Packet) bool {
	// We use an unbound connection but we offer a connection-oriented service. So, we need to
	// supply the packet's destination address.
	router.UpdateNetAddrFromAddrPort(p.DstAddr, l.remote)
	select {
	case l.queue <- p:
	default:
		return false
	}
	return true
}

func (l *siblingLink) SendBlocking(p *router.Packet) {
	// We use an unbound connection but we offer a connection-oriented service. So, we need to
	// supply the packet's destination address.
	router.UpdateNetAddrFromAddrPort(p.DstAddr, l.remote)
	l.queue <- p
}

type internalLink struct {
	queue chan *router.Packet
}

// NewInternalLink returns a internal link over the UdpIpUnderlay.
//
// TODO(multi_underlay): we get the connection ready made. In the future we will be making it
// and the conn argument will be gone.
func (u *provider) NewInternalLink(
	conn router.BatchConn, qSize int, metrics router.InterfaceMetrics) router.Link {

	queue := make(chan *router.Packet, qSize)
	c := &udpConnection{
		conn:         conn,
		queue:        queue,
		name:         "internal",
		ifID:         0,
		metrics:      metrics,
		receiverDone: make(chan struct{}),
		senderDone:   make(chan struct{}),
	}
	l := &internalLink{
		queue: queue,
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	u.allConnections[netip.AddrPort{}] = c
	u.allLinks[netip.AddrPort{}] = l
	return l
}

func (l *internalLink) start(ctx context.Context) {
}

func (l *internalLink) stop() {
}

func (l *internalLink) Scope() router.LinkScope {
	return router.Internal
}

func (l *internalLink) IsUp() bool {
	return true
}

func (l *internalLink) BFDSession() router.BFDSession {
	return nil
}

func (l *internalLink) IfID() uint16 {
	return 0
}

func (l *internalLink) Remote() netip.AddrPort {
	return netip.AddrPort{}
}

// The packet's destination is already in the packet's meta-data.
func (l *internalLink) Send(p *router.Packet) bool {
	select {
	case l.queue <- p:
	default:
		return false
	}
	return true
}

// The packet's destination is already in the packet's meta-data.
func (l *internalLink) SendBlocking(p *router.Packet) {
	l.queue <- p
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
