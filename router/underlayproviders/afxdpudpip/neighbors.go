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
	is4      bool
	isLoop   bool // If true, the cache is just a stub.
}

// seekNeighbor ensures there is an entry for the given IP and attempts to populate
// it from the kernel's neighbor table.
func (cache *neighborCache) seekNeighbor(remoteIP *netip.Addr) {
	if cache.isLoop {
		return
	}
	cache.Lock()
	defer cache.Unlock()

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
}

// queryKernelNeighbor looks up an IP address in the kernel's neighbor table.
// Returns the MAC address if found and reachable, nil otherwise.
func (cache *neighborCache) queryKernelNeighbor(ip netip.Addr) *[6]byte {
	neighbors, err := netlink.NeighList(0, 0) // All interfaces, all families
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
func (cache *neighborCache) get(ip netip.Addr) (*[6]byte, chan *router.Packet) {
	if cache.isLoop {
		return &zeroMacAddr, nil
	}

	entry, exists := cache.mappings[ip]
	if !exists {
		// New destination (e.g. internalLink). Create entry and try kernel lookup.
		entry = neighbor{
			backlog: make(chan *router.Packet, neighborMaxBacklog),
		}
		entry.mac = cache.queryKernelNeighbor(ip)
		cache.mappings[ip] = entry
	}

	if entry.mac != nil {
		return entry.mac, nil
	}
	return nil, entry.backlog
}

// getBacklog returns the backlog channel for the given IP.
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
					cache.mappings[ip] = entry
					changed = true
				}
			}
		case unix.RTM_DELNEIGH:
			if entry.mac != nil {
				entry.mac = nil
				cache.mappings[ip] = entry
				changed = true
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
	onUpdate func(netip.Addr),
) *neighborCache {
	return &neighborCache{
		name:     name,
		localMAC: localMAC,
		localIP:  localIP,
		mappings: make(map[netip.Addr]neighbor),
		onUpdate: onUpdate,
		done:     make(chan struct{}),
		is4:      localIP.Is4(),
		isLoop:   ([6]byte(localMAC) == zeroMacAddr),
	}
}
