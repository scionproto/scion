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
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/router"
)

// TestSendBacklogKeepsPacketsWhileUnresolved checks that a flush which runs
// before the peer's MAC address is known leaves the queued packets alone.
// Those packets must wait for the flush that follows a successful lookup.
//
// The link reaches this state whenever the kernel drops its neighbour entry.
// That wakes the flush while the MAC address is still missing.
func TestSendBacklogKeepsPacketsWhileUnresolved(t *testing.T) {
	local := netip.MustParseAddrPort("192.0.2.1:30042")
	remote := netip.MustParseAddrPort("192.0.2.2:30042")

	l := &linkPTP{
		localAddr:  &local,
		remoteAddr: &remote,
		txConns: []*udpConnection{{
			localMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01},
			queue:    make(chan *router.Packet, 8),
		}},
		metrics:      newTestMetrics(),
		pool:         makeTestPool(t, 4),
		backlogCheck: make(chan struct{}, 1),
		is4:          true,
	}
	// The peer is known but its MAC address is not, and a lookup is already running.
	// This is the state the kernel leaves behind when it drops the neighbour entry.
	l.neighbors = &neighborCache{
		localMAC: l.txConns[0].localMAC,
		localIP:  local.Addr(),
		is4:      true,
		mappings: map[netip.Addr]neighbor{
			remote.Addr(): {
				mac:     nil,
				probing: true,
				backlog: make(chan *router.Packet, NeighborCacheMaxBacklog),
			},
		},
	}
	backlog := l.neighbors.mappings[remote.Addr()].backlog

	// A packet arrives before the MAC address is known and waits in the backlog.
	backlog <- newTestPacket(t, []byte("scion payload"))

	l.sendBacklog()

	assert.Len(t, backlog, 1, "flush dropped a packet while the MAC address was unknown")
	assert.Empty(t, l.txConns[0].queue, "flush sent a packet without a MAC address")
}

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
// A failing run reaches that path and would otherwise panic on a nil counter.
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
