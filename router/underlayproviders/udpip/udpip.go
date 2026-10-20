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
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/stun"
	"github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/bfd"
)

var (
	errResolveOnSiblingLink  = errors.New("unsupported address resolution on sibling link")
	errResolveOnExternalLink = errors.New("unsupported address resolution on external link")
	errInvalidServiceAddress = errors.New("invalid service address")
	errDuplicateRemote       = errors.New("duplicate remote address")
)

// An interface to enable unit testing.
type ConnOpener interface {
	// Creates a connection as specified.
	Open(l netip.AddrPort, r netip.AddrPort, c *conn.Config) (router.BatchConn, error)
	// Informs the underlay of whether the Opener can create multiple connections with
	// the same local address. If not, then this underlay will share the internal connection
	// with all the Sibling links in addition to the internal link. This generally complicates
	// testing.
	UDPCanReuseLocal() bool
}

// The default ConnOpener for this underlay: opens a UDP BatchConn.
type uo struct{}

func (uo) Open(l netip.AddrPort, r netip.AddrPort, c *conn.Config) (router.BatchConn, error) {
	return conn.New(l, r, c)
}

func (uo) UDPCanReuseLocal() bool {
	// By default we follow the local UDP capabilities. Unit tests can chose to model one behavior
	// or the other.
	return conn.UDPCanReuseLocal()
}

// provider implements UnderlayProvider by making and returning Udp/Ip links.
//
// This is currently the only implementation. The goal of splitting out this code from the router
// is to enable other implementations.
type provider struct {
	mu                 sync.Mutex // Prevents race between adding connections and Start/Stop.
	batchSize          int
	allLinks           map[netip.AddrPort]udpLink
	allConnections     []*udpConnection
	connOpener         ConnOpener // uo{}, except for unit tests
	svc                *router.Services[netip.AddrPort]
	internalConnection *udpConnection // Because we can share it w/ sibling links
	internalHashSeed   uint32         // ...in which case, this too is shared.
	receiveBufferSize  int
	sendBufferSize     int
	dispatchStart      uint16
	dispatchEnd        uint16
	dispatchRedirect   uint16
}

// udpLink is implemented by all the links of this provider.
// The provider calls start and stop with its mutex held.
// Links ignore all but the first call to start.
type udpLink interface {
	router.Link
	start(ctx context.Context, procQs []chan *router.Packet, pool router.PacketPool)
	stop()
	receive(size int, srcAddr *net.UDPAddr, p *router.Packet)
}

func init() {
	// Register ourselves as an underlay provider. The registration consists of a constructor, not
	// a provider object, because multiple router instances each must have their own underlay
	// provider. The provider is not re-entrant.
	router.AddUnderlay("udpip", newProvider)
}

// Topology reloads need it.
var _ router.LinkDeleter = (*provider)(nil)

// New instantiates a new instance of the provider for exclusive use by the caller.
// TODO(multi_underlay): batchSize should be an underlay-specific config.
func newProvider(batchSize int, receiveBufferSize int, sendBufferSize int) router.UnderlayProvider {
	return &provider{
		batchSize:         batchSize,
		allLinks:          make(map[netip.AddrPort]udpLink),
		connOpener:        uo{},
		svc:               router.NewServices[netip.AddrPort](),
		receiveBufferSize: receiveBufferSize,
		sendBufferSize:    sendBufferSize,
	}
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
	// This underlay does not add any header of its own: the UDP socket API manages the header
	// independently.
	return 0
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
	defer u.mu.Unlock()
	if len(procQs) == 0 {
		// Pointless to run without any processor of incoming traffic
		return
	}

	// Links MUST be started before connections. Given that this is an internal mater, we don't pay
	// the price of checking at use time.
	for _, l := range u.allLinks {
		l.start(ctx, procQs, pool)
	}
	for _, c := range u.allConnections {
		c.start(u.batchSize, pool)
	}
}

func (u *provider) Stop() {
	u.mu.Lock()
	defer u.mu.Unlock()

	for _, c := range u.allConnections {
		c.stop()
	}
	for _, l := range u.allLinks {
		l.stop()
	}
}

func (u *provider) DelLink(l router.Link) {
	u.mu.Lock()
	defer u.mu.Unlock()

	var ul udpLink
	for a, x := range u.allLinks {
		if x == l && a != (netip.AddrPort{}) { // Not the internal link.
			ul = x
			delete(u.allLinks, a)
			break
		}
	}
	if ul == nil {
		return
	}
	// Stop the link first, so that it refuses packets before
	// its connection drains its queue.
	ul.stop()
	for i, c := range u.allConnections {
		if c.link == ul {
			c.stop()
			u.allConnections = slices.Delete(u.allConnections, i, i+1)
			break
		}
	}
}

// udpConnection is essentially a BatchConn with a sending queue and a demultiplexer. The rest is
// about logs and metrics. This allows UDP connections to be shared between links when needed (for
// example, only linux allows UDP connected sockets to share the same local address, which is needed
// if sibling links are to have distinct connections).
type udpConnection struct {
	conn    router.BatchConn
	name    string  // for logs. It's more informative than ifID.
	link    udpLink // Link with exclusive use of the connection.
	queue   chan *router.Packet
	metrics *router.InterfaceMetrics
	pool    router.PacketPool

	// links maps remote addresses to the links that share this connection.
	// It is nil if the connection isn't shared. Links come and go while
	// the receiver runs, so the map is replaced rather than modified.
	links atomic.Pointer[map[netip.AddrPort]udpLink]

	// done is closed by stop.
	// The queue is never closed because links may still send to it.
	done         chan struct{}
	receiverDone chan struct{}
	senderDone   chan struct{}
	started      bool
	stopped      bool
	running      atomic.Bool
	connected    bool // If true, the underlying UDP socket is connected
}

func newUDPConnection(
	conn router.BatchConn,
	name string,
	link udpLink,
	queue chan *router.Packet,
	metrics *router.InterfaceMetrics,
	connected bool,
) *udpConnection {
	return &udpConnection{
		conn:         conn,
		name:         name,
		link:         link,
		queue:        queue,
		metrics:      metrics, // send() needs them :-(
		done:         make(chan struct{}),
		receiverDone: make(chan struct{}),
		senderDone:   make(chan struct{}),
		connected:    connected,
	}
}

// setLink makes the connection deliver packets from remote to l.
// Callers must hold the provider's mutex.
func (u *udpConnection) setLink(remote netip.AddrPort, l udpLink) {
	links := maps.Clone(*u.links.Load())
	links[remote] = l
	u.links.Store(&links)
}

// unsetLink undoes setLink. Callers must hold the provider's mutex.
func (u *udpConnection) unsetLink(remote netip.AddrPort) {
	links := maps.Clone(*u.links.Load())
	delete(links, remote)
	u.links.Store(&links)
}

// start puts the connection in the running state. In that state, the connection can deliver
// incoming packets and ignores packets present on its input channel.
// Only the first call has an effect, and none after stop.
func (u *udpConnection) start(batchSize int, pool router.PacketPool) {
	if u.started || u.stopped {
		return
	}
	u.started = true
	u.pool = pool
	u.running.Store(true)

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
// stopped when this method returns. The first call to stop is acted upon regardless of how many
// times start was called.
func (u *udpConnection) stop() {
	if u.stopped {
		return
	}
	u.stopped = true
	if !u.started {
		u.conn.Close()
		return
	}
	u.running.Store(false)
	u.conn.Close() // Unblock receiver
	close(u.done)  // Unblock sender
	<-u.receiverDone
	<-u.senderDone
	drain(u.queue, u.pool)
}

// drain returns the packets in queue to the pool.
func drain(queue chan *router.Packet, pool router.PacketPool) {
	for {
		select {
		case p := <-queue:
			pool.Put(p)
		default:
			return
		}
	}
}

func (u *udpConnection) receive(batchSize int, pool router.PacketPool) {
	log.Debug("Receive", "connection", u.name)

	// A collection of socket messages, as the readBatch API expects them. We keep using the same
	// collection, call after call; only replacing the buffer.
	msgs := conn.NewReadMessages(batchSize)

	// An array of corresponding packet references. Each corresponds to one msg.
	// The packet owns the buffer that we set in the matching msg, plus the metadata that we'll add.
	packets := make([]*router.Packet, batchSize)
	numReusable := 0 // unused buffers from previous loop

	for u.running.Load() {
		// collect packets.

		// Give a new buffer to the msgs elements that have been used in the previous loop.
		for i := range batchSize - numReusable {
			p := pool.Get()
			packets[i] = p
			msgs[i].Buffers[0] = p.RawPacket
		}

		// Fill the packets
		numReusable = len(msgs)
		numPkts, err := u.conn.ReadBatch(msgs)
		if err != nil {
			log.Debug("Error while reading batch", "connection", u.name, "err", err)
			continue
		}
		numReusable -= numPkts
		links := u.links.Load()
		for i, msg := range msgs[:numPkts] {

			// Update size; readBatch does not.
			size := msg.N
			p := packets[i]
			p.RawPacket = p.RawPacket[:size]

			// Demultiplex to a link.
			if links != nil {
				// For a shared connection we have a map of links by remote address.
				srcAddr := msg.Addr.(*net.UDPAddr).AddrPort()
				l, found := (*links)[srcAddr]
				if found {
					l.receive(size, msg.Addr.(*net.UDPAddr), p)
					continue
				}
			}

			// Either there is no map, or the address isn't in it. In both cases
			// hand the packet to our distinguished link. That's either the internal link, or a
			// connected link. There's always one or the other, else it's a panicable offense.
			u.link.receive(size, msg.Addr.(*net.UDPAddr), p)
		}
	}

	// We have to stop receiving. Return the unused packets to the pool to avoid creating
	// a memory leak (the process is not required to exit - e.g. in tests).
	for _, p := range packets[batchSize-numReusable : batchSize] {
		pool.Put(p)
	}
}

func readUpTo(
	queue <-chan *router.Packet,
	done <-chan struct{},
	n int,
	needsBlocking bool,
	pkts []*router.Packet,
) int {
	i := 0
	if needsBlocking {
		select {
		case p := <-queue:
			pkts[i] = p
			i++
		case <-done:
			return i
		}
	}

	for ; i < n; i++ {
		select {
		case p := <-queue:
			pkts[i] = p
		default:
			return i
		}
	}
	return i
}

func (u *udpConnection) send(batchSize int, pool router.PacketPool) {
	log.Debug("Send", "connection", u.name)

	// We use this somewhat like a ring buffer.
	pkts := make([]*router.Packet, batchSize)

	// We use this as a temporary buffer, but allocate it just once
	// to save on garbage handling.
	msgs := make(conn.Messages, batchSize)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
	}

	queue := u.queue
	conn := u.conn
	metrics := u.metrics
	toWrite := 0

	// Packets still held when the sender stops belong to the pool.
	defer func() {
		for _, p := range pkts[:toWrite] {
			pool.Put(p)
		}
	}()

	for u.running.Load() {
		// Top-up our batch.
		toWrite += readUpTo(
			queue,
			u.done,
			batchSize-toWrite,
			toWrite == 0, pkts[toWrite:],
		)
		if toWrite == 0 {
			continue // stopped
		}

		// Turn the packets into underlay messages that WriteBatch can send.
		for i, p := range pkts[:toWrite] {
			msgs[i].Buffers[0] = p.RawPacket
			msgs[i].Addr = nil
			// If we're using a connected socket we must not specify the address. It might cause
			// redundant route queries and the address might not even be set in the packet.
			// Otherwise, we must specify the address.
			if !u.connected {
				msgs[i].Addr = (*net.UDPAddr)(p.RemoteAddr)
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
			pool.Put(p)
		}
		if written != toWrite {
			// Only one is dropped at this time. We'll retry the rest.
			sc := router.ClassOfSize(len(pkts[written].RawPacket))
			metrics[sc].DroppedPacketsInvalid.Inc()
			pool.Put(pkts[written])
			toWrite -= (written + 1)
			// Shift the leftovers to the head of the buffers.
			for i := range toWrite {
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

// A connectedLink creates an exclusive underlying point-to-point connection. Such a link does not
// need to specify a destination address and receives all the traffic from that connection. Such a
// link is used as an external link and, under some conditions, as a sibling link.
type connectedLink struct {
	procQs     []chan *router.Packet
	name       string // For logs
	egressQ    chan *router.Packet
	done       <-chan struct{} // Closed when the connection stops.
	metrics    *router.InterfaceMetrics
	pool       router.PacketPool
	bfdSession *bfd.Session
	closed     atomic.Bool
	started    bool
	seed       uint32
	ifID       uint16
	scope      router.LinkScope
}

// NewExternalLink returns an external link over the UDP/IP underlay. It is always implemented with
// a connectedLink.
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
	return u.newConnectedLink(qSize, bfd, localAddr, remoteAddr, ifID, metrics, router.External)
}

func (u *provider) newConnectedLink(
	qSize int,
	bfd *bfd.Session,
	localAddr netip.AddrPort,
	remoteAddr netip.AddrPort,
	ifID uint16,
	metrics *router.InterfaceMetrics,
	scope router.LinkScope, // Since this can be used for either Sibling or External
) (router.Link, error) {
	conn, err := u.connOpener.Open(localAddr, remoteAddr,
		&conn.Config{ReceiveBufferSize: u.receiveBufferSize, SendBufferSize: u.sendBufferSize})
	if err != nil {
		return nil, err
	}
	queue := make(chan *router.Packet, qSize)
	el := &connectedLink{
		name:       remoteAddr.String(),
		egressQ:    queue,
		metrics:    metrics,
		bfdSession: bfd,
		seed:       makeHashSeed(),
		ifID:       ifID,
		scope:      scope,
	}
	// No demux lookup ever for this connection.
	c := newUDPConnection(conn, el.name, el, queue, metrics, true)
	el.done = c.done
	u.allConnections = append(u.allConnections, c)
	u.allLinks[remoteAddr] = el
	return el, nil
}

func (l *connectedLink) start(
	ctx context.Context,
	procQs []chan *router.Packet,
	pool router.PacketPool,
) {
	if l.started {
		return
	}
	l.started = true
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

func (l *connectedLink) stop() {
	l.closed.Store(true)
	if l.bfdSession == nil {
		return
	}
	l.bfdSession.Close()
}

func (l *connectedLink) IfID() uint16 {
	return l.ifID
}

func (l *connectedLink) Metrics() *router.InterfaceMetrics {
	return l.metrics
}

func (l *connectedLink) Scope() router.LinkScope {
	return l.scope
}

func (l *connectedLink) BFDSession() *bfd.Session {
	return l.bfdSession
}

func (l *connectedLink) IsUp() bool {
	return l.bfdSession == nil || l.bfdSession.IsUp()
}

// Resolve should not be useful on an external link so we don't implement it yet.
func (l *connectedLink) Resolve(p *router.Packet, host addr.Host, port uint16) error {
	return errResolveOnExternalLink
}

func (l *connectedLink) Send(p *router.Packet) bool {
	// TODO(multi_underlay): With #4892, Send frees the packets it refuses.
	// This check and the one in detachedLink.Send must then free p too.
	if l.closed.Load() {
		return false
	}
	select {
	case l.egressQ <- p:
	default:
		return false
	}
	l.drainIfClosed()
	return true
}

func (l *connectedLink) SendBlocking(p *router.Packet) {
	// We use a bound and connected socket so we don't need to specify the destination.
	select {
	case l.egressQ <- p:
	case <-l.done:
		l.pool.Put(p)
		return
	}
	l.drainIfClosed()
}

// drainIfClosed must be called after queuing a packet. If the link stopped meanwhile,
// its connection may have drained the queue already, and nothing else would return
// the packet to the pool.
func (l *connectedLink) drainIfClosed() {
	if l.closed.Load() {
		drain(l.egressQ, l.pool)
	}
}

func (l *connectedLink) receive(size int, srcAddr *net.UDPAddr, p *router.Packet) {
	metrics := l.metrics
	sc := router.ClassOfSize(size)
	metrics[sc].InputPacketsTotal.Inc()
	metrics[sc].InputBytesTotal.Add(float64(size))

	p.Link = l
	// The src address does not need to be recorded in the packet. The link has all the relevant
	// information.

	procID, ok := computeProcID(p.RawPacket, len(l.procQs), l.seed)
	if !ok {
		l.pool.Put(p)
		metrics[sc].DroppedPacketsInvalid.Inc()
		return
	}
	select {
	case l.procQs[procID] <- p:
	default:
		l.pool.Put(p)
		metrics[sc].DroppedPacketsBusyProcessor.Inc()
	}
}

// A detached link is an implementation of a siblingLink that does not require
// an exclusive underlying point-to-point connection. Instead, it shares the
// unconnected batchConn that the internal link also uses.
type detachedLink struct {
	procQs     []chan *router.Packet
	name       string // For logs
	conn       *udpConnection
	egressQ    chan<- *router.Packet
	metrics    *router.InterfaceMetrics
	pool       router.PacketPool
	bfdSession *bfd.Session
	remote     *net.UDPAddr
	closed     atomic.Bool
	started    bool
	seed       uint32
}

// NewSiblingLink returns a sibling link over the UDP/IP underlay. It may be implemented with either
// a detachedLink or a connectedLink, depending on the OS features.
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

	// If we have linux support, we use connected links, even though the local address is the same
	// for all sibling links.
	if u.connOpener.UDPCanReuseLocal() {
		return u.newConnectedLink(qSize, bfd, localAddr, remoteAddr, 0, metrics, router.Sibling)
	}
	return u.newDetachedLink(bfd, remoteAddr, metrics)
}

func (u *provider) newDetachedLink(
	bfd *bfd.Session,
	remoteAddr netip.AddrPort,
	metrics *router.InterfaceMetrics,
) (router.Link, error) {
	// All detached links re-use the internal connection.
	c := u.internalConnection
	if c == nil {
		// The router isn't supposed to do this. This is an internal error.
		panic("newSiblingLink called before newInternalLink")
	}

	sl := &detachedLink{
		name:       remoteAddr.String(),
		conn:       c,
		egressQ:    c.queue,
		metrics:    metrics,
		bfdSession: bfd,
		remote:     net.UDPAddrFromAddrPort(remoteAddr),
		seed:       u.internalHashSeed,
	}
	u.allLinks[remoteAddr] = sl
	return sl, nil
}

func (l *detachedLink) start(
	ctx context.Context,
	procQs []chan *router.Packet,
	pool router.PacketPool,
) {
	if l.started {
		return
	}
	l.started = true
	// procQs and pool are never known before all configured links have been instantiated.  So we
	// get them only now. We didn't need it earlier since the connections have not been started yet.
	l.procQs = procQs
	l.pool = pool
	// The shared connection may be running already. It must not deliver to us before now.
	l.conn.setLink(l.remote.AddrPort(), l)
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

func (l *detachedLink) stop() {
	l.closed.Store(true)
	l.conn.unsetLink(l.remote.AddrPort())
	if l.bfdSession == nil {
		return
	}
	l.bfdSession.Close()
}

func (l *detachedLink) IfID() uint16 {
	return 0
}

func (l *detachedLink) Metrics() *router.InterfaceMetrics {
	return l.metrics
}

func (l *detachedLink) Scope() router.LinkScope {
	return router.Sibling
}

func (l *detachedLink) BFDSession() *bfd.Session {
	return l.bfdSession
}

func (l *detachedLink) IsUp() bool {
	return l.bfdSession == nil || l.bfdSession.IsUp()
}

// Resolve should not be useful on a sibling link so we don't implement it yet.
func (l *detachedLink) Resolve(p *router.Packet, host addr.Host, port uint16) error {
	return errResolveOnSiblingLink
}

func (l *detachedLink) Send(p *router.Packet) bool {
	// The shared connection keeps sending,
	// so packets that slip in after stop still leave.
	if l.closed.Load() {
		return false
	}
	// We use an unbound connection but we offer a connection-oriented service. So, we need to
	// supply the packet's destination address. Trying to reuse the packet's RemoteAddress storage
	// is pointless: if we loan l.remote we avoid a copy and still discard at most one address. This
	// is safe because we treat p.RemoteAddr as immutable and the router main code doesn't touch it.
	p.RemoteAddr = unsafe.Pointer(l.remote)
	select {
	case l.egressQ <- p:
	default:
		return false
	}
	return true
}

func (l *detachedLink) SendBlocking(p *router.Packet) {
	// Same as Send(). We must supply the destination address.
	p.RemoteAddr = unsafe.Pointer(l.remote)
	l.egressQ <- p
}

func (l *detachedLink) receive(size int, srcAddr *net.UDPAddr, p *router.Packet) {
	metrics := l.metrics
	sc := router.ClassOfSize(size)
	metrics[sc].InputPacketsTotal.Inc()
	metrics[sc].InputBytesTotal.Add(float64(size))

	p.Link = l
	// The src address does not need to be recorded in the packet. The link has all the relevant
	// information.

	procID, ok := computeProcID(p.RawPacket, len(l.procQs), l.seed)
	if !ok {
		l.pool.Put(p)
		metrics[sc].DroppedPacketsInvalid.Inc()
		return
	}
	select {
	case l.procQs[procID] <- p:
	default:
		l.pool.Put(p)
		metrics[sc].DroppedPacketsBusyProcessor.Inc()
	}
}

type internalLink struct {
	procQ            chan *router.Packet
	procQs           []chan *router.Packet
	egressQ          chan *router.Packet
	procStop         chan struct{}
	procDone         chan struct{}
	metrics          *router.InterfaceMetrics
	pool             router.PacketPool
	svc              *router.Services[netip.AddrPort]
	started          bool
	seed             uint32
	dispatchStart    uint16
	dispatchEnd      uint16
	dispatchRedirect uint16
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

	if u.internalConnection != nil {
		// We don't want to support this and the router doesn't do it. This is an internal error.
		panic("More than one internal link")
	}
	localAddr, err := conn.ResolveAddrPort(local)
	if err != nil {
		return nil, serrors.Wrap("resolving local address", err)
	}
	conn, err := u.connOpener.Open(
		localAddr, netip.AddrPort{},
		&conn.Config{ReceiveBufferSize: u.receiveBufferSize, SendBufferSize: u.sendBufferSize})
	if err != nil {
		return nil, err
	}
	u.internalHashSeed = makeHashSeed()
	queue := make(chan *router.Packet, qSize)
	il := &internalLink{
		egressQ:          queue,
		metrics:          metrics,
		svc:              u.svc,
		seed:             u.internalHashSeed,
		dispatchStart:    u.dispatchStart,
		dispatchEnd:      u.dispatchEnd,
		dispatchRedirect: u.dispatchRedirect,
	}
	// Might be exclusive to internal links, but still not connected.
	c := newUDPConnection(conn, "internal", il, queue, metrics, false)

	if !u.connOpener.UDPCanReuseLocal() {
		// In this case we will share this connection with sibling links, so the connection has a
		// demux map.
		c.links.Store(&map[netip.AddrPort]udpLink{})
	}

	u.allLinks[netip.AddrPort{}] = il
	u.internalConnection = c
	u.allConnections = append(u.allConnections, c)
	return il, nil
}

func (l *internalLink) start(
	ctx context.Context,
	procQs []chan *router.Packet,
	pool router.PacketPool,
) {
	if l.started {
		return
	}
	l.started = true
	maxCap := 0
	for _, q := range procQs {
		maxCap = max(maxCap, cap(q))
	}
	l.procQ = make(chan *router.Packet, maxCap)
	l.procStop = make(chan struct{})
	l.procDone = make(chan struct{})

	// procQs and pool are never known before all configured links have been instantiated. So we
	// get them only now. We didn't need it earlier since the connections have not been started yet.
	l.procQs = procQs
	l.pool = pool

	go func() {
		defer log.HandlePanic()
		l.runProcessor()
	}()
}

func (l *internalLink) runProcessor() {
	for {
		select {
		case p := <-l.procQ:
			err := l.processPacket(p)
			if err != nil {
				log.Debug("Error processing packet", "err", err)
				sc := router.ClassOfSize(len(p.RawPacket))
				l.metrics[sc].DroppedPacketsInvalid.Inc()
				l.pool.Put(p)
				continue
			}
			egressLink := p.Link
			if egressLink == nil {
				sc := router.ClassOfSize(len(p.RawPacket))
				l.metrics[sc].DroppedPacketsInvalid.Inc()
				l.pool.Put(p)
				continue
			}
			if !egressLink.Send(p) {
				sc := router.ClassOfSize(len(p.RawPacket))
				l.metrics[sc].DroppedPacketsBusyForwarder.Inc()
				l.pool.Put(p)
				continue
			}
		case <-l.procStop:
			for {
				select {
				case p := <-l.procQ:
					sc := router.ClassOfSize(len(p.RawPacket))
					l.metrics[sc].DroppedPacketsBusyProcessor.Inc()
					l.pool.Put(p)
				default:
					close(l.procDone)
					return
				}
			}
		}
	}
}

func (l *internalLink) processPacket(pkt *router.Packet) error {
	if stun.Is(pkt.RawPacket) {
		// Process STUN packet
		txid, err := stun.ParseBindingRequest(pkt.RawPacket)
		if err != nil {
			return serrors.Wrap("processing STUN packet", err)
		}
		resp := stun.Response(txid, (*net.UDPAddr)(pkt.RemoteAddr).AddrPort())
		pkt.RawPacket = pkt.RawPacket[:len(resp)]
		copy(pkt.RawPacket, resp)
		return nil
	}
	// Drop packet
	pkt.Link = nil
	return nil
}

func (l *internalLink) stop() {
	if !l.started {
		return
	}
	close(l.procStop)
	<-l.procDone
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
	// attach a RemoteAddr to the packet (besides; it could be a different type).  So, RemoteAddr is
	// not generally usable. We must allocate a new object. The precautions needed to pool them cost
	// more than the pool saves (verified experimentally).
	p.RemoteAddr = unsafe.Pointer(&net.UDPAddr{
		IP:   dstAddr.AsSlice(),
		Zone: dstAddr.Zone(),
		Port: int(port),
	})
	return nil
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

func (l *internalLink) receive(size int, srcAddr *net.UDPAddr, p *router.Packet) {
	metrics := l.metrics
	sc := router.ClassOfSize(size)
	metrics[sc].InputPacketsTotal.Inc()
	metrics[sc].InputBytesTotal.Add(float64(size))

	p.Link = l
	// This is an unconnected link. We must record the src address in case the packet is turned
	// around, e.g., by SCMP.
	p.RemoteAddr = unsafe.Pointer(srcAddr)

	var q chan *router.Packet
	procID, ok := computeProcID(p.RawPacket, len(l.procQs), l.seed)
	if ok {
		q = l.procQs[procID]
	} else {
		q = l.procQ
	}
	select {
	case q <- p:
	default:
		l.pool.Put(p)
		metrics[sc].DroppedPacketsBusyProcessor.Inc()
	}
}

// computeProcID computes the processor ID for a given packet provided by the slice data. It assumes
// that numProcRoutines is non-negative and not larger than 4294967295. hashSeed is used for hash
// computation. If data is clearly not a valid SCION packet, it returns ok=false. Otherwise, it
// returns a processor ID smaller than numProcRoutines and ok=true.
// Specifically for STUN packets, the check for valid SCION packets fails since the part of the STUN
// header that overlaps with the SCION common header NextHdr field contains value 0x21, which is not
// a valid L4 protocol type. Therefore, STUN packets will always result in ok=false.
// If we ever have a protocol type assigned to value 0x21, we need to revisit this function.
func computeProcID(data []byte, numProcRoutines int, hashSeed uint32) (uint32, bool) {
	if len(data) < slayers.CmnHdrLen {
		return uint32(numProcRoutines), false
	}

	switch slayers.L4ProtocolType(data[4]) {
	case slayers.L4TCP, slayers.L4UDP, slayers.L4SCMP, slayers.L4BFD,
		slayers.HopByHopClass, slayers.End2EndClass,
		slayers.ExperimentationAndTesting, slayers.ExperimentationAndTesting2:
	default:
		return uint32(numProcRoutines), false
	}

	dstHostAddrLen := slayers.AddrType(data[9] >> 4 & 0xf).Length()
	srcHostAddrLen := slayers.AddrType(data[9] & 0xf).Length()
	addrHdrLen := 2*addr.IABytes + srcHostAddrLen + dstHostAddrLen
	if len(data) < slayers.CmnHdrLen+addrHdrLen {
		return uint32(numProcRoutines), false
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

	return s % uint32(numProcRoutines), true
}
