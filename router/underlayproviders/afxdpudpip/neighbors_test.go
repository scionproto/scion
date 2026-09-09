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
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/scionproto/scion/router"
)

// makeTestPool builds a router.PacketPool backed by a buffered channel.
// The test needs it only to keep a failing run from blocking forever:
// the drop path calls pool.Put, and the zero value holds a nil channel.
// The pool fields are unexported, which is why this needs reflection.
func makeTestPool(t *testing.T, size int) router.PacketPool {
	t.Helper()

	var p router.PacketPool
	f := reflect.ValueOf(&p).Elem().FieldByName("pool")
	reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).
		Elem().Set(reflect.MakeChan(f.Type(), size))
	return p
}

// newTestMetrics fills in the counters that the packet drop path touches.
// A drop would otherwise panic on a nil counter.
func newTestMetrics() *router.InterfaceMetrics {
	m := new(router.InterfaceMetrics)
	for sc := range m {
		for tt := range m[sc].DroppedPacketsBusyForwarder {
			m[sc].DroppedPacketsBusyForwarder[tt] = prometheus.NewCounter(
				prometheus.CounterOpts{Name: "test_dropped"})
		}
	}
	return m
}

// TestFinishPacketHoldsWhileUnresolved checks that the internal link keeps a
// packet whose destination MAC address is still unknown, and sends it once the
// address turns up. Dropping it instead loses the first packet to every host,
// which a one-shot ping never recovers from.
func TestFinishPacketHoldsWhileUnresolved(t *testing.T) {
	local := netip.MustParseAddrPort("192.0.2.1:30042")
	remote := netip.MustParseAddr("192.0.2.2")

	l := &linkInternal{
		localAddr: &local,
		txConns: []*udpConnection{{
			localMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01},
			queue:    make(chan *router.Packet, 8),
		}},
		metrics: newTestMetrics(),
		pool:    makeTestPool(t, 4),
		is4:     true,
	}
	l.packHeader()

	var mac [6]byte
	var known bool
	l.neighbors = &neighborCache{
		localMAC:     l.txConns[0].localMAC,
		localIP:      local.Addr(),
		is4:          true,
		kernelLookup: func(netip.Addr) ([6]byte, bool) { return mac, known },
		mappings:     map[netip.Addr]neighbor{remote: {probing: true}},
		conf:         NeighborConfig{}.withDefaults(),
	}

	p := newTestPacket(t, []byte("scion payload"))
	setRemoteAddr(p, remote.AsSlice(), 30042)
	assert.False(t, l.finishPacket(p, false), "packet was sent without a MAC address")
	assert.Len(t, l.neighbors.mappings[remote].queue, 1, "packet was not held")

	// The kernel answers the probe. The next lookup resolves the address and has
	// to send what waited for it.
	mac, known = [6]byte{0x02, 0, 0, 0, 0, 0x02}, true

	p = newTestPacket(t, []byte("scion payload"))
	setRemoteAddr(p, remote.AsSlice(), 30042)
	require.True(t, l.finishPacket(p, false), "packet was dropped despite a known MAC address")
	assert.Equal(t, mac[:], p.RawPacket[0:6], "wrong destination MAC address")
	assert.Empty(t, l.neighbors.mappings[remote].queue, "held packet was not sent")
	assert.Len(t, l.txConns[0].queue, 1, "held packet did not reach the send queue")
}

// TestNeighborQueueLimits checks both bounds: a neighbor holds QueueLen packets
// and the newest wins, and the link holds QueueTotal packets in all.
func TestNeighborQueueLimits(t *testing.T) {
	first := netip.MustParseAddr("192.0.2.2")
	second := netip.MustParseAddr("192.0.2.3")
	cache := &neighborCache{
		pool: makeTestPool(t, 8),
		mappings: map[netip.Addr]neighbor{
			first:  {probing: true},
			second: {probing: true},
		},
		conf: NeighborConfig{QueueLen: 1, QueueTotal: 2}.withDefaults(),
	}

	oldest := newTestPacket(t, []byte("oldest"))
	kept := newTestPacket(t, []byte("newest"))
	evicted, held := cache.hold(first, oldest)
	require.True(t, held)
	require.Nil(t, evicted)

	evicted, held = cache.hold(first, kept)
	require.True(t, held)
	assert.Equal(t, oldest, evicted, "the evicted packet must come back to be counted")
	assert.Equal(t, []*router.Packet{kept}, cache.mappings[first].queue,
		"a full queue keeps the newest packet, as the kernel does")
	assert.Equal(t, 1, cache.queued)

	_, held = cache.hold(second, newTestPacket(t, []byte("other neighbor")))
	require.True(t, held)
	assert.Equal(t, 2, cache.queued)

	// The link is now full, so a third neighbor gets nothing.
	third := netip.MustParseAddr("192.0.2.4")
	cache.mappings[third] = neighbor{probing: true}
	_, held = cache.hold(third, newTestPacket(t, []byte("too much for the link")))
	assert.False(t, held, "the total limit was ignored")
	assert.Equal(t, 2, cache.queued)
}

// TestNeighborCacheEviction checks that the table stops growing. Without a bound
// a sender aiming at addresses that never resolve grows it forever.
func TestNeighborCacheEviction(t *testing.T) {
	cache := &neighborCache{
		pool:         makeTestPool(t, 8),
		mappings:     map[netip.Addr]neighbor{},
		kernelLookup: func(netip.Addr) ([6]byte, bool) { return zeroMacAddr, false },
		conf:         NeighborConfig{CacheMax: 4}.withDefaults(),
	}
	for i := range 40 {
		ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		cache.lock.Lock()
		cache.get(ip)
		cache.lock.Unlock()
	}
	assert.LessOrEqual(t, len(cache.mappings), 4, "the cache grew past its limit")
}

// TestBuildHeaderHoldsWhileUnresolved is the point-to-point link's version of
// TestFinishPacketHoldsWhileUnresolved. It also covers that no header is cached
// before the MAC address is known.
func TestBuildHeaderHoldsWhileUnresolved(t *testing.T) {
	local := netip.MustParseAddrPort("192.0.2.1:30042")
	remote := netip.MustParseAddrPort("192.0.2.2:30042")

	l := &linkPTP{
		localAddr:  &local,
		remoteAddr: &remote,
		txConns: []*udpConnection{{
			localMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01},
			queue:    make(chan *router.Packet, 8),
		}},
		metrics: newTestMetrics(),
		pool:    makeTestPool(t, 4),
		is4:     true,
	}

	var mac [6]byte
	var known bool
	l.neighbors = &neighborCache{
		localMAC:     l.txConns[0].localMAC,
		localIP:      local.Addr(),
		is4:          true,
		kernelLookup: func(netip.Addr) ([6]byte, bool) { return mac, known },
		mappings:     map[netip.Addr]neighbor{remote.Addr(): {probing: true}},
		conf:         NeighborConfig{}.withDefaults(),
	}

	assert.False(t, l.finishPacket(newTestPacket(t, []byte("scion payload")), false),
		"packet was sent without a MAC address")
	assert.Nil(t, l.header.Load(), "header was cached without a MAC address")
	assert.Len(t, l.neighbors.mappings[remote.Addr()].queue, 1, "packet was not held")

	mac, known = [6]byte{0x02, 0, 0, 0, 0, 0x02}, true

	p := newTestPacket(t, []byte("scion payload"))
	require.True(t, l.finishPacket(p, false), "packet was dropped despite a known MAC address")
	assert.Equal(t, mac[:], p.RawPacket[0:6], "wrong destination MAC address")
	assert.Empty(t, l.neighbors.mappings[remote.Addr()].queue, "held packet was not sent")
	assert.Len(t, l.txConns[0].queue, 1, "held packet did not reach the send queue")
}

// TestAwaitNeighborWaitsForResolution checks that the BFD gate holds until the
// peer MAC address is known. A session started earlier would send its first
// packet into a drop and then wait a full detection interval.
func TestAwaitNeighborWaitsForResolution(t *testing.T) {
	remote := netip.MustParseAddrPort("192.0.2.2:30042")

	l := &linkPTP{
		remoteAddr:      &remote,
		neighborUpdated: make(chan struct{}, 1),
		stopped:         make(chan struct{}),
		is4:             true,
	}
	var mac [6]byte
	var known bool
	l.neighbors = &neighborCache{
		localIP:      netip.MustParseAddr("192.0.2.1"),
		is4:          true,
		kernelLookup: func(netip.Addr) ([6]byte, bool) { return mac, known },
		mappings:     map[netip.Addr]neighbor{remote.Addr(): {probing: true}},
	}

	done := make(chan bool, 1)
	go func() { done <- l.awaitNeighbor(remote.Addr()) }()

	select {
	case <-done:
		t.Fatal("the gate opened before the MAC address was known")
	case <-time.After(20 * time.Millisecond):
	}

	// The netlink watcher reports the resolution.
	l.neighbors.lock.Lock()
	l.neighbors.mappings[remote.Addr()] = neighbor{
		mac:   [6]byte{0x02, 0, 0, 0, 0, 0x02},
		known: true,
	}
	l.neighbors.lock.Unlock()
	l.neighborUpdated <- struct{}{}

	select {
	case ok := <-done:
		assert.True(t, ok, "the gate reported a stop instead of a resolution")
	case <-time.After(time.Second):
		t.Fatal("the gate stayed shut after the MAC address became known")
	}
}

// TestAwaitNeighborStops checks that a link that stops while
// waiting does not start its BFD session.
func TestAwaitNeighborStops(t *testing.T) {
	remote := netip.MustParseAddrPort("192.0.2.2:30042")

	l := &linkPTP{
		remoteAddr:      &remote,
		neighborUpdated: make(chan struct{}, 1),
		stopped:         make(chan struct{}),
		is4:             true,
	}
	l.neighbors = &neighborCache{
		localIP:      netip.MustParseAddr("192.0.2.1"),
		is4:          true,
		kernelLookup: func(netip.Addr) ([6]byte, bool) { return zeroMacAddr, false },
		mappings:     map[netip.Addr]neighbor{remote.Addr(): {probing: true}},
	}

	done := make(chan bool, 1)
	go func() { done <- l.awaitNeighbor(remote.Addr()) }()
	l.running.Store(true)
	l.stop()

	select {
	case ok := <-done:
		assert.False(t, ok, "the gate opened for a stopped link")
	case <-time.After(time.Second):
		t.Fatal("the gate ignored the stop")
	}
}

// TestLoopbackNeighborResolves checks the loopback stub:
// it has no MAC address to resolve, so the gate must not block a link on it.
func TestLoopbackNeighborResolves(t *testing.T) {
	cache := &neighborCache{isLoop: true, mappings: map[netip.Addr]neighbor{}}
	assert.True(t, cache.resolved(netip.MustParseAddr("127.0.0.1")))
}

// TestSeekNeighborSendsQueued checks that a lookup outside the packet path also
// sends what waited for the address. That lookup produces no netlink update,
// so leaving the flush to the watcher strands the packets.
func TestSeekNeighborSendsQueued(t *testing.T) {
	remote := netip.MustParseAddr("192.0.2.2")
	flushed := make(chan netip.Addr, 1)

	var mac [6]byte
	var known bool
	cache := &neighborCache{
		pool:         makeTestPool(t, 4),
		localIP:      netip.MustParseAddr("192.0.2.1"),
		is4:          true,
		localMAC:     net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01},
		kernelLookup: func(netip.Addr) ([6]byte, bool) { return mac, known },
		mappings:     map[netip.Addr]neighbor{remote: {probing: true}},
		conf:         NeighborConfig{}.withDefaults(),
		onUpdate:     func(ip netip.Addr) { flushed <- ip },
	}
	_, held := cache.hold(remote, newTestPacket(t, []byte("waiting")))
	require.True(t, held)

	mac, known = [6]byte{0x02, 0, 0, 0, 0, 0x02}, true
	cache.seekNeighbor(&remote)

	select {
	case got := <-flushed:
		assert.Equal(t, remote, got)
	default:
		t.Fatal("no flush requested, the queued packet is stranded")
	}
}

// TestSweepGivesUp checks the kernel's rule: an address that does not answer is
// probed a few times and then the packets waiting for it are dropped.
// Holding them longer only delivers them after the sender stopped waiting.
func TestSweepGivesUp(t *testing.T) {
	remote := netip.MustParseAddr("192.0.2.2")
	dropped := make(chan []*router.Packet, 1)
	cache := &neighborCache{
		pool:         makeTestPool(t, 4),
		localIP:      netip.MustParseAddr("192.0.2.1"),
		is4:          true,
		kernelLookup: func(netip.Addr) ([6]byte, bool) { return zeroMacAddr, false },
		mappings:     map[netip.Addr]neighbor{remote: {probing: true}},
		conf:         NeighborConfig{ProbeAttempts: 3}.withDefaults(),
		onDrop:       func(pkts []*router.Packet) { dropped <- pkts },
	}
	waiting := newTestPacket(t, []byte("waiting"))
	_, held := cache.hold(remote, waiting)
	require.True(t, held)

	// The first sweeps only re-probe.
	cache.sweep()
	assert.Len(t, cache.mappings[remote].queue, 1, "the packet was dropped too early")
	assert.Empty(t, dropped)

	// The last one gives up.
	cache.sweep()
	cache.sweep()
	select {
	case got := <-dropped:
		assert.Equal(t, []*router.Packet{waiting}, got)
	default:
		t.Fatal("the packet is still waiting for an address that never answers")
	}
	assert.Empty(t, cache.mappings[remote].queue)
	assert.Equal(t, 0, cache.queued)
}

// TestNudStatesUsable checks which kernel states count as a usable address.
// A neighbor enters DELAY and PROBE when it is used after going stale, and its MAC
// address is good throughout. Treating those as unknown holds up traffic to every
// neighbor that goes quiet for a while.
func TestNudStatesUsable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state int
		want  bool
	}{
		{"reachable", netlink.NUD_REACHABLE, true},
		{"stale", netlink.NUD_STALE, true},
		{"delay", netlink.NUD_DELAY, true},
		{"probe", netlink.NUD_PROBE, true},
		{"permanent", netlink.NUD_PERMANENT, true},
		{"noarp", netlink.NUD_NOARP, true},
		{"incomplete", netlink.NUD_INCOMPLETE, false},
		{"failed", netlink.NUD_FAILED, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.state&nudUsable != 0)
		})
	}
}
