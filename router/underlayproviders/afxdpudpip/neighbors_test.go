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

// TestFinishPacketDropsWhileUnresolved checks that the internal link drops a
// packet whose destination MAC address is still unknown,
// and sends it once the address is known.
func TestFinishPacketDropsWhileUnresolved(t *testing.T) {
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
	}

	p := newTestPacket(t, []byte("scion payload"))
	setRemoteAddr(p, remote.AsSlice(), 30042)
	assert.False(t, l.finishPacket(p, false), "packet was sent without a MAC address")

	// The kernel answers the probe.
	mac, known = [6]byte{0x02, 0, 0, 0, 0, 0x02}, true

	p = newTestPacket(t, []byte("scion payload"))
	setRemoteAddr(p, remote.AsSlice(), 30042)
	require.True(t, l.finishPacket(p, false), "packet was dropped despite a known MAC address")
	assert.Equal(t, mac[:], p.RawPacket[0:6], "wrong destination MAC address")
}

// TestBuildHeaderDropsWhileUnresolved is the point-to-point link's version of
// TestFinishPacketDropsWhileUnresolved. It also covers that no header is cached
// before the MAC address is known.
func TestBuildHeaderDropsWhileUnresolved(t *testing.T) {
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
	}

	assert.False(t, l.finishPacket(newTestPacket(t, []byte("scion payload")), false),
		"packet was sent without a MAC address")
	assert.Nil(t, l.header.Load(), "header was cached without a MAC address")

	mac, known = [6]byte{0x02, 0, 0, 0, 0, 0x02}, true

	p := newTestPacket(t, []byte("scion payload"))
	require.True(t, l.finishPacket(p, false), "packet was dropped despite a known MAC address")
	assert.Equal(t, mac[:], p.RawPacket[0:6], "wrong destination MAC address")
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
