// Copyright 2025 SCION Association
//
// SPDX-License-Identifier: Apache-2.0

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

// Neighbor cache parameters.
const (
	neighborMaxBacklog = 3 // Number of packets pending resolution.
)

var zeroMacAddr = [6]byte{0, 0, 0, 0, 0, 0}

// neighbor represents one neighbor entry.
type neighbor struct {
	mac     *[6]byte
	backlog chan *router.Packet
	probing bool // True while a probe is in-flight; prevents probe storms.
}

// neighborCache manages IP to MAC address mappings.
// It queries the kernel's neighbor table on first use and subscribes to
// netlink notifications (RTM_NEWNEIGH / RTM_DELNEIGH) for subsequent updates.
type neighborCache struct {
	sync.Mutex
	name     string
	localMAC net.HardwareAddr
	localIP  netip.Addr
	pool     router.PacketPool
	mappings map[netip.Addr]neighbor
	onUpdate func(netip.Addr) // Called (outside lock) when a tracked neighbor's MAC changes.
	done     chan struct{}
	running  atomic.Bool
	ifIndex  int  // Kernel interface index for filtering neighbor entries.
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
	cache.Lock()

	entry, exists := cache.mappings[*remoteIP]
	if !exists {
		entry = neighbor{
			backlog: make(chan *router.Packet, neighborMaxBacklog),
		}
	}
	if entry.mac == nil {
		entry.mac = cache.queryKernelNeighbor(*remoteIP)
	}
	cache.mappings[*remoteIP] = entry
	needsProbe := entry.mac == nil
	cache.Unlock()

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
		log.Debug("Failed to probe neighbor", "cache", cache.name, "remote", remoteIP, "err", err)
		return
	}
	conn.Write([]byte{0})
	conn.Close()
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
		if n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT) != 0 {
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
// Caller must hold cache.Lock.
func (cache *neighborCache) get(ip netip.Addr) (*[6]byte, chan *router.Packet) {
	if cache.isLoop {
		return &zeroMacAddr, nil
	}

	entry, exists := cache.mappings[ip]
	if !exists {
		entry = neighbor{
			backlog: make(chan *router.Packet, neighborMaxBacklog),
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
// Caller must hold cache.Lock.
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
	err := netlink.NeighSubscribeWithOptions(ch, cache.done, netlink.NeighSubscribeOptions{
		ErrorCallback: func(err error) {
			log.Debug("Netlink neighbor subscription error", "cache", cache.name, "err", err)
		},
	})
	if err != nil {
		log.Error("Failed to subscribe to neighbor updates", "cache", cache.name, "err", err)
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

		cache.Lock()
		entry, tracked := cache.mappings[ip]
		if !tracked {
			cache.Unlock()
			continue
		}

		changed := false
		switch update.Type {
		case unix.RTM_NEWNEIGH:
			if update.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT) != 0 &&
				len(update.HardwareAddr) == 6 {
				mac := [6]byte(update.HardwareAddr)
				if entry.mac == nil || *entry.mac != mac {
					entry.mac = &mac
					entry.probing = false
					cache.mappings[ip] = entry
					changed = true
				}
			} else if update.State&netlink.NUD_FAILED != 0 {
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
			entry.probing = false
			if entry.mac != nil {
				entry.mac = nil
				cache.mappings[ip] = entry
				changed = true
			} else {
				cache.mappings[ip] = entry
			}
		}
		cache.Unlock()

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
		done:     make(chan struct{}),
		ifIndex:  ifIndex,
		is4:      localIP.Is4(),
		isLoop:   ([6]byte(localMAC) == zeroMacAddr),
	}
}
