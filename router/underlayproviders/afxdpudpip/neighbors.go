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

//go:build linux

package afxdpudpip

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/router"
)

// NeighborCacheMaxBacklog is the maximum number of packets that can be queued
// while waiting for ARP/NDP resolution for a given neighbor. ARP/NDP typically
// resolves in milliseconds, but without a backlog the first packets after startup
// or a MAC change are always dropped. This matters for BFD session establishment,
// where a dropped initial packet costs a full BFD interval before retry.
// A small value (3) is sufficient to hold a BFD packet plus a couple of data
// packets during the brief resolution window without wasting memory per neighbor.
var NeighborCacheMaxBacklog = 3

// nudUsable is the set of NUD states in which a neighbor's MAC address
// is considered valid for forwarding.
const nudUsable = netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_PERMANENT

var (
	zeroMacAddr = [6]byte{0, 0, 0, 0, 0, 0}
	probeBuf    = []byte{0}
)

// neighbor represents one neighbor entry.
type neighbor struct {
	mac     *[6]byte
	backlog chan *router.Packet
	probing bool // True while a probe is in-flight; prevents probe storms.
}

// neighborCache manages IP to MAC address mappings scoped to a single
// network interface (ifIndex). It queries the kernel's neighbor table on
// first use and subscribes to netlink notifications (RTM_NEWNEIGH /
// RTM_DELNEIGH) for subsequent updates.
//
// When the MAC for a destination is not yet known, outgoing packets are
// buffered in a per-neighbor backlog channel while a UDP probe triggers
// ARP/NDP resolution via the kernel. The onUpdate callback notifies the
// owning link when a neighbor's MAC changes so it can rebuild headers
// or drain backlogged packets.
//
// On loopback interfaces (isLoop), the cache acts as a stub: get() always
// returns a zero MAC and no backlog.
//
// Callers must hold lock when calling get() and getBacklog().
type neighborCache struct {
	lock sync.Mutex

	name     string
	localMAC net.HardwareAddr
	localIP  netip.Addr
	pool     router.PacketPool
	mappings map[netip.Addr]neighbor
	// onUpdate is called (outside lock) when a tracked neighbor's MAC changes.
	onUpdate func(netip.Addr)
	done     chan struct{}
	running  atomic.Bool
	ifIndex  int // Kernel interface index for filtering neighbor entries.
	is4      bool
	isLoop   bool // If true, the cache is just a stub.
}

// seekNeighbor ensures there is an entry for the given IP and attempts to populate
// it from the kernel's neighbor table. If not found, it triggers ARP resolution
// via the kernel by sending a UDP probe. The result will be picked up
// asynchronously by watchNeighborUpdates.
func (cache *neighborCache) seekNeighbor(remoteIP *netip.Addr) {
	if cache.isLoop {
		return
	}
	cache.lock.Lock()

	entry, ok := cache.mappings[*remoteIP]
	if !ok {
		entry = neighbor{
			backlog: make(chan *router.Packet, NeighborCacheMaxBacklog),
		}
	}
	if entry.mac == nil {
		entry.mac = cache.queryKernelNeighbor(*remoteIP)
	}
	cache.mappings[*remoteIP] = entry
	needsProbe := entry.mac == nil
	cache.lock.Unlock()

	if needsProbe {
		cache.probeNeighbor(*remoteIP)
	}
}

// probeNeighbor triggers ARP/NDP resolution by sending a UDP packet via the kernel
// network stack. The kernel handles neighbor resolution as a side effect. The probe
// targets the discard port (9), so it is harmless to the remote host.
func (cache *neighborCache) probeNeighbor(remoteIP netip.Addr) {
	laddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(cache.localIP, 0))
	raddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(remoteIP, 9))
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		log.Debug("Failed to probe neighbor",
			"cache", cache.name, "remote", remoteIP, "err", err)
		return
	}
	// The write forces the kernel to perform ARP/NDP resolution for remoteIP.
	// The payload is irrelevant; the side effect is what matters.
	_, _ = conn.Write(probeBuf)
	_ = conn.Close()
}

// queryKernelNeighbor looks up an IP address in the kernel's neighbor table.
// Returns the MAC address if found and reachable, nil otherwise.
func (cache *neighborCache) queryKernelNeighbor(ip netip.Addr) *[6]byte {
	family := unix.AF_INET6
	if cache.is4 {
		family = unix.AF_INET
	}
	neighbors, err := netlink.NeighList(cache.ifIndex, family)
	if err != nil {
		log.Debug("Failed to list neighbors", "err", err)
		return nil
	}

	for _, n := range neighbors {
		neighIP, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		if neighIP != ip {
			continue
		}
		// Check if the neighbor is reachable
		if n.State&nudUsable != 0 {
			if len(n.HardwareAddr) == 6 {
				mac := [6]byte(n.HardwareAddr)
				return &mac
			}
		}
	}
	return nil
}

// get returns the MAC address for the given IP, or nil if not resolved.
// Returns a backlog channel for queuing packets while resolution is pending.
// Caller must hold cache.lock.
func (cache *neighborCache) get(ip netip.Addr) (*[6]byte, chan *router.Packet) {
	if cache.isLoop {
		return &zeroMacAddr, nil
	}

	entry, ok := cache.mappings[ip]
	if !ok {
		entry = neighbor{
			backlog: make(chan *router.Packet, NeighborCacheMaxBacklog),
		}
		cache.mappings[ip] = entry
	}

	if entry.mac == nil {
		// Covers both new entries and previously-failed resolutions
		// (e.g. seekNeighbor at startup before the peer was reachable).
		entry.mac = cache.queryKernelNeighbor(ip)
		if entry.mac != nil {
			entry.probing = false
			cache.mappings[ip] = entry
		} else if !entry.probing {
			entry.probing = true
			cache.mappings[ip] = entry
			go cache.probeNeighbor(ip)
		}
	}

	if entry.mac != nil {
		return entry.mac, nil
	}
	return nil, entry.backlog
}

// getBacklog returns the backlog channel for the given IP.
// Returns nil if the IP is not tracked.
// Caller must hold cache.lock.
func (cache *neighborCache) getBacklog(ip netip.Addr) chan *router.Packet {
	if cache.isLoop {
		return nil
	}
	return cache.mappings[ip].backlog
}

// watchNeighborUpdates subscribes to kernel neighbor table changes via netlink
// and updates the cache when tracked entries change.
func (cache *neighborCache) watchNeighborUpdates() {
	ch := make(chan netlink.NeighUpdate, 64)
	err := netlink.NeighSubscribeWithOptions(
		ch, cache.done, netlink.NeighSubscribeOptions{
			ErrorCallback: func(err error) {
				log.Debug("Netlink neighbor subscription error",
					"cache", cache.name, "err", err)
			},
		},
	)
	if err != nil {
		log.Error("Failed to subscribe to neighbor updates",
			"cache", cache.name, "err", err)
		return
	}

	for update := range ch {
		if update.LinkIndex != cache.ifIndex {
			continue
		}

		ip, ok := netip.AddrFromSlice(update.IP)
		if !ok {
			continue
		}

		cache.lock.Lock()
		entry, tracked := cache.mappings[ip]
		if !tracked {
			cache.lock.Unlock()
			continue
		}

		changed := false
		switch update.Type {
		case unix.RTM_NEWNEIGH:
			// Neighbor resolved or refreshed: update MAC if it's new or changed.
			// NUD_REACHABLE: confirmed reachable (ARP reply / NDP NA received).
			// NUD_STALE: reachable but not recently confirmed; still usable.
			// NUD_PERMANENT: statically configured, never expires.
			if update.State&nudUsable != 0 && len(update.HardwareAddr) == 6 {
				mac := [6]byte(update.HardwareAddr)
				if entry.mac == nil || *entry.mac != mac {
					entry.mac = &mac
					entry.probing = false
					cache.mappings[ip] = entry
					changed = true
				}
			} else if update.State&netlink.NUD_FAILED != 0 {
				// Resolution failed (no ARP/NDP reply after retries).
				// Clear probing so the next get() can re-probe.
				entry.probing = false
				if entry.mac != nil {
					entry.mac = nil
					cache.mappings[ip] = entry
					changed = true
				} else {
					cache.mappings[ip] = entry
				}
			}
		case unix.RTM_DELNEIGH:
			// Neighbor removed from kernel table (GC, manual flush, etc.).
			entry.probing = false
			if entry.mac != nil {
				entry.mac = nil
				cache.mappings[ip] = entry
				changed = true
			} else {
				cache.mappings[ip] = entry
			}
		default:
			log.Debug("Unexpected netlink message type",
				"cache", cache.name, "type", update.Type)
		}
		cache.lock.Unlock()

		// Notify the link outside the lock so it can rebuild headers
		// or drain backlogged packets.
		if changed && cache.onUpdate != nil {
			cache.onUpdate(ip)
		}
	}
}

func (cache *neighborCache) start(pool router.PacketPool) {
	wasRunning := cache.running.Swap(true)
	if wasRunning {
		return
	}
	cache.pool = pool
	if cache.isLoop {
		return
	}
	cache.done = make(chan struct{})
	go func() {
		defer log.HandlePanic()
		cache.watchNeighborUpdates()
	}()
}

func (cache *neighborCache) stop() {
	wasRunning := cache.running.Swap(false)
	if cache.isLoop {
		return
	}
	if wasRunning {
		close(cache.done)
	}
}

func newNeighborCache(
	name string,
	localMAC net.HardwareAddr,
	localIP netip.Addr,
	ifIndex int,
	onUpdate func(netip.Addr),
) *neighborCache {
	return &neighborCache{
		name:     name,
		localMAC: localMAC,
		localIP:  localIP,
		mappings: make(map[netip.Addr]neighbor),
		onUpdate: onUpdate,
		ifIndex:  ifIndex,
		is4:      localIP.Is4(),
		isLoop:   ([6]byte(localMAC) == zeroMacAddr),
	}
}
