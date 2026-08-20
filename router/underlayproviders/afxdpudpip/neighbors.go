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
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/router"
)

// neighborRetryInterval is how often a link re-probes a peer whose MAC address
// is still unknown. Only the BFD startup path waits for a neighbor,
// and a session that cannot start is already down, so a slow retry is enough.
const neighborRetryInterval = 500 * time.Millisecond

// nudUsable is the set of NUD states in which a neighbor's MAC address
// is considered valid for forwarding.
const nudUsable = netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_PERMANENT

var (
	zeroMacAddr = [6]byte{0, 0, 0, 0, 0, 0}
	probeBuf    = []byte{0}
)

// neighbor represents one neighbor entry.
type neighbor struct {
	mac [6]byte
	// queue holds packets waiting for the MAC address, oldest first.
	// The kernel does the same for its own traffic ([NeighborConfig.QueueLen]),
	// and without it every first packet to a neighbor is lost.
	queue []*router.Packet
	// probes counts how often this address was asked for since it was last known.
	// The kernel counts solicitations the same way and gives up at mcast_solicit.
	probes  int
	known   bool // True once mac holds a resolved address.
	probing bool // True while a probe is in-flight; prevents probe storms.
}

// neighborCache manages IP to MAC address mappings scoped to a single
// network interface (ifIndex). It queries the kernel's neighbor table on
// first use and subscribes to netlink notifications
// (RTM_NEWNEIGH / RTM_DELNEIGH) for subsequent updates.
//
// A packet for an unresolved MAC waits in the neighbor's queue while a UDP probe
// triggers ARP/NDP resolution via the kernel. The [neighborCache.onUpdate]
// callback tells the owning link that a neighbor's MAC changed,
// which is when it rebuilds its header and sends what is queued.
//
// On loopback interfaces ([neighborCache.isLoop]), the cache acts as a stub:
// [neighborCache.get] always returns a zero MAC.
//
// Callers must hold [neighborCache.lock] when calling [neighborCache.get].
type neighborCache struct {
	lock sync.Mutex

	name     string
	localMAC net.HardwareAddr
	localIP  netip.Addr
	pool     router.PacketPool
	mappings map[netip.Addr]neighbor
	// onUpdate is called (outside lock) when a tracked neighbor's MAC changes.
	onUpdate func(netip.Addr)
	// onDrop is called (outside lock) with packets the cache gives up on.
	// The link counts them and returns them to the pool.
	onDrop func([]*router.Packet)
	// kernelLookup replaces the kernel neighbor table lookup.
	// Tests set it to keep the lookup off the host; it is nil in production.
	kernelLookup func(netip.Addr) ([6]byte, bool)
	done         chan struct{}
	conf         NeighborConfig
	queued       int // Packets held across all entries, bounded by conf.QueueTotal.
	running      atomic.Bool
	ifIndex      int // Kernel interface index for filtering neighbor entries.
	is4          bool
	isLoop       bool // If true, the cache is just a stub.
}

// seekNeighbor ensures there is an entry for the given IP and attempts to populate
// it from the kernel's neighbor table.
// If not found, it triggers ARP resolution via the kernel by sending a UDP probe.
// The result will be picked up asynchronously by [neighborCache.watchNeighborUpdates].
func (cache *neighborCache) seekNeighbor(remoteIP *netip.Addr) {
	if cache.isLoop {
		return
	}
	cache.lock.Lock()

	entry, tracked := cache.mappings[*remoteIP]
	if !tracked {
		cache.evictLocked()
	}
	flush := false
	if !entry.known {
		entry.mac, entry.known = cache.queryKernel(*remoteIP)
		flush = entry.known && len(entry.queue) > 0
	}
	cache.mappings[*remoteIP] = entry
	needsProbe := !entry.known
	cache.lock.Unlock()

	// This path resolves an address without a netlink update behind it,
	// so it has to send what waited for the address itself.
	// Leaving that to the next update strands the packets: no update is coming.
	if flush && cache.onUpdate != nil {
		cache.onUpdate(*remoteIP)
	}
	if needsProbe {
		cache.probeNeighbor(*remoteIP)
	}
}

// probeNeighbor triggers ARP/NDP resolution by sending a UDP packet via the kernel
// network stack. The kernel handles neighbor resolution as a side effect.
// The probe targets the discard port (9), so it is harmless to the remote host.
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

// queryKernel looks up an IP address in the kernel's neighbor table,
// or in the stub that a test installed in [neighborCache.kernelLookup].
func (cache *neighborCache) queryKernel(ip netip.Addr) ([6]byte, bool) {
	if cache.kernelLookup != nil {
		return cache.kernelLookup(ip)
	}
	return cache.queryKernelNeighbor(ip)
}

// queryKernelNeighbor looks up an IP address in the kernel's neighbor table.
// It reports whether the neighbor was found and is reachable.
func (cache *neighborCache) queryKernelNeighbor(ip netip.Addr) ([6]byte, bool) {
	family := unix.AF_INET6
	if cache.is4 {
		family = unix.AF_INET
	}
	neighbors, err := netlink.NeighList(cache.ifIndex, family)
	if err != nil {
		log.Debug("Failed to list neighbors", "err", err)
		return zeroMacAddr, false
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
				return [6]byte(n.HardwareAddr), true
			}
		}
	}
	return zeroMacAddr, false
}

// get returns the MAC address for the given IP and reports whether it is known.
// A miss starts a probe, and the caller queues the packet with [neighborCache.hold].
//
// The last return value reports that this call resolved the MAC while packets
// were already queued. Resolving here bypasses watchNeighborUpdates,
// the usual trigger for a flush, so the caller must send what is
// queued once it has released the lock.
//
// Caller must hold [neighborCache.lock].
func (cache *neighborCache) get(ip netip.Addr) (mac [6]byte, known, flush bool) {
	if cache.isLoop {
		return zeroMacAddr, true, false
	}

	entry, tracked := cache.mappings[ip]
	if !tracked {
		cache.evictLocked()
	}
	if !entry.known {
		// Covers both new entries and previously-failed resolutions
		// (e.g. [neighborCache.seekNeighbor] at startup before the peer was reachable).
		entry.mac, entry.known = cache.queryKernel(ip)
		if entry.known {
			entry.probing, entry.probes = false, 0
			flush = len(entry.queue) > 0
		} else if !entry.probing {
			entry.probing = true
			go cache.probeNeighbor(ip)
		}
		cache.mappings[ip] = entry
	}
	return entry.mac, entry.known, flush
}

// evictLocked makes room for one more entry. Entries go without regard for age:
// the cache is a cache, and a wrongly evicted neighbor costs one kernel lookup.
// What matters is that a sender aiming at addresses that never resolve cannot
// grow the table without end.
//
// Caller must hold [neighborCache.lock].
func (cache *neighborCache) evictLocked() {
	for len(cache.mappings) >= cache.conf.CacheMax {
		for ip, entry := range cache.mappings {
			cache.dropQueue(entry)
			delete(cache.mappings, ip)
			break
		}
	}
}

// hold queues a packet until the MAC address for ip is known. It reports false
// when the caller must drop the packet instead, which happens once the neighbor
// holds [NeighborConfig.QueueLen] packets or the link holds [NeighborConfig.QueueTotal].
//
// A neighbor whose queue is full gives up its oldest packet for the newest,
// as the kernel does. The returned packet is the one that lost its place,
// and the caller counts and frees it.
//
// Caller must hold [neighborCache.lock].
func (cache *neighborCache) hold(ip netip.Addr, p *router.Packet) (*router.Packet, bool) {
	entry, ok := cache.mappings[ip]
	if !ok || entry.known || cache.conf.QueueLen <= 0 {
		return nil, false
	}
	var evicted *router.Packet
	switch {
	case len(entry.queue) >= cache.conf.QueueLen:
		evicted = entry.queue[0]
		entry.queue = append(entry.queue[:0], entry.queue[1:]...)
		cache.queued--
	case cache.queued >= cache.conf.QueueTotal:
		return nil, false
	}
	entry.queue = append(entry.queue, p)
	cache.queued++
	cache.mappings[ip] = entry
	return evicted, true
}

// sweep mirrors the kernel's neighbor timer. It probes every address that is still
// unresolved and drops what is queued for an address that has not answered
// after [NeighborConfig.ProbeAttempts] tries.
// The kernel calls that state NUD_FAILED and empties the queue in the same way.
func (cache *neighborCache) sweep() {
	var expired []*router.Packet
	var reprobe []netip.Addr

	cache.lock.Lock()
	for ip, entry := range cache.mappings {
		if entry.known || (len(entry.queue) == 0 && !entry.probing) {
			continue
		}
		entry.probes++
		if entry.probes >= cache.conf.ProbeAttempts {
			expired = append(expired, entry.queue...)
			cache.queued -= len(entry.queue)
			entry.queue = nil
			entry.probing = false
			entry.probes = 0
		} else {
			reprobe = append(reprobe, ip)
		}
		cache.mappings[ip] = entry
	}
	cache.lock.Unlock()

	for i := range reprobe {
		cache.seekNeighbor(&reprobe[i])
	}
	if len(expired) > 0 && cache.onDrop != nil {
		cache.onDrop(expired)
	}
}

// takeQueue removes and returns the packets waiting for ip.
// The caller sends them and must not hold [neighborCache.lock].
func (cache *neighborCache) takeQueue(ip netip.Addr) []*router.Packet {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	entry, ok := cache.mappings[ip]
	if !ok || len(entry.queue) == 0 {
		return nil
	}
	queue := entry.queue
	cache.queued -= len(queue)
	entry.queue = nil
	cache.mappings[ip] = entry
	return queue
}

// dropQueue returns the packets waiting in the entry to the pool.
// It is used when resolution fails, where holding them any longer only pins buffers.
// Caller must hold [neighborCache.lock].
func (cache *neighborCache) dropQueue(entry neighbor) neighbor {
	for _, p := range entry.queue {
		cache.pool.Put(p)
	}
	cache.queued -= len(entry.queue)
	entry.queue = nil
	return entry
}

// resolved reports whether the MAC for the given IP is known.
// It takes the lock, so callers must not hold it.
func (cache *neighborCache) resolved(ip netip.Addr) bool {
	if cache.isLoop {
		return true
	}
	cache.lock.Lock()
	defer cache.lock.Unlock()
	return cache.mappings[ip].known
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
				if !entry.known || entry.mac != mac {
					entry.mac, entry.known = mac, true
					entry.probing, entry.probes = false, 0
					cache.mappings[ip] = entry
					changed = true
				}
			} else if update.State&netlink.NUD_FAILED != 0 {
				// Resolution failed (no ARP/NDP reply after retries).
				// Clear probing so the next [neighborCache.get] can re-probe.
				// Nothing will ever send what is queued, so let it go.
				entry.probing = false
				entry = cache.dropQueue(entry)
				if entry.known {
					entry.mac, entry.known = zeroMacAddr, false
					changed = true
				}
				cache.mappings[ip] = entry
			}
		case unix.RTM_DELNEIGH:
			// Neighbor removed from kernel table (GC, manual flush, etc.).
			entry.probing = false
			if entry.known {
				entry.mac, entry.known = zeroMacAddr, false
				changed = true
			}
			cache.mappings[ip] = entry
		default:
			log.Debug("Unexpected netlink message type",
				"cache", cache.name, "type", update.Type)
		}
		cache.lock.Unlock()

		// Notify the link outside the lock so it can rebuild its header.
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
	go func() {
		defer log.HandlePanic()
		t := time.NewTicker(cache.conf.ProbeInterval)
		defer t.Stop()
		for {
			select {
			case <-cache.done:
				return
			case <-t.C:
				cache.sweep()
			}
		}
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
	conf NeighborConfig,
	onUpdate func(netip.Addr),
) *neighborCache {
	return &neighborCache{
		name:     name,
		localMAC: localMAC,
		localIP:  localIP,
		mappings: make(map[netip.Addr]neighbor),
		onUpdate: onUpdate,
		conf:     conf.withDefaults(),
		ifIndex:  ifIndex,
		is4:      localIP.Is4(),
		isLoop:   ([6]byte(localMAC) == zeroMacAddr),
	}
}
