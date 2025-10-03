// Copyright 2025 SCION Association
//
// SPDX-License-Identifier: Apache-2.0

package afpacketudpip

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/router"
)

// ARP cache parameters. The longish TTL is because I suspect that linux rate limits responses,
// so, we have to resolve stuff other than a SCION router not too often.
// Requests for unresolved entries that have a backlog are sent once per tick.
const (
	neighborTick       = 1000 * time.Millisecond // Cache clock period.
	neighborTTL        = 600                     // Time to live of resolved entry (in ticks).
	neighborTTR        = 3                       // TTL threshold for resolution (in ticks).
	neighborMaxBacklog = 3                       // Number of packets pending resolution.
)

// FF02:0000:0000:0000:0000:0001:FF00:0000/104
var ndpMcastPrefix = []byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1, 0xff}
var zeroMacAddr = [6]byte{0, 0, 0, 0, 0, 0}

type neighborState int

const (
	None neighborState = iota
	Incomplete
	Reachable
	Stale
	Probe
)

// neighbor represents one neighbor. This is a bit simplistic compared to Linux's arp
// life-cycle. There is a small backlog of packets waiting for resolution, (Because too much of the
// SCION test code assumes infaillible packet delivery).
type neighbor struct {
	mac *[6]byte
	// timer keeps track of the time that the entry has been resolved or pending:
	timer int
	// TODO(jiceatscion): the whole neighbor management is getting clumsy. Reorg.
	backlog chan *router.Packet
	state   neighborState
}

// neighborCache is a cache of IP address to MAC address mapping.
// It is not automatically
// re-entrant: you must use lock() and unlock() explicitly. The reason is that we have two different
// usage patterns; one of which needs to manipulate another object in the same critical section.
// There is a builtin entry ticker. Calling start() will activate it and stop() will
// deactivate it.
type neighborCache struct {
	sync.Mutex
	name       string
	localMAC   net.HardwareAddr
	localIP    netip.Addr
	pool       router.PacketPool
	mappings   map[netip.Addr]neighbor
	egressQ    chan *router.Packet
	tickerDone chan struct{}
	running    atomic.Bool
	is4        bool
	isLoop     bool // If true, the cache is just a stub. All MAC addresses are zero.
}

// TODO(jiceatscion): This can end-up being called from the critical section. Not ideal.
func (cache *neighborCache) seekNeighbor(remoteIP *netip.Addr) {
	if cache.isLoop {
		return
	}
	p := cache.pool.Get()
	packNeighborReq(p, &cache.localIP, cache.localMAC, remoteIP, cache.is4)
	select {
	case cache.egressQ <- p:
	default:
	}
}

// Lookup returns the mac address associated with the given IP, or nil if not known. A new (pending)
// entry is created if none existed. A resolution is triggered if the entry did not exist.
// The pending entry will exist for as long as specified by the TTR. This function either returns
// a non-nil address or a non-nil backlog channel. Unresolved packets can be put on that queue
// for later sending.
func (cache *neighborCache) get(ip netip.Addr) (*[6]byte, chan *router.Packet) {
	if cache.isLoop {
		return &zeroMacAddr, nil
	}

	entry := cache.mappings[ip]
	switch entry.state {
	case None:
		// Whole new entry
		entry.state = Incomplete
		entry.backlog = make(chan *router.Packet, neighborMaxBacklog)
		entry.timer = neighborTTR // We have that long to resolve it.
		cache.mappings[ip] = entry
		cache.seekNeighbor(&ip)
		return nil, entry.backlog
	case Incomplete:
		// Already started resolving. Don't do anything more for now. You get the backlog.
		return nil, entry.backlog
	case Reachable, Probe:
		// All good. If probe, the ticker works on refreshing.
		return entry.mac, nil
	case Stale:
		// Since we do use it; ask the ticker to refresh.
		entry.state = Probe
		return entry.mac, nil
	default:
		panic("Illegal entry state")
	}
}

func (cache *neighborCache) getBacklog(ip netip.Addr) chan *router.Packet {
	if cache.isLoop {
		return nil
	}
	return cache.mappings[ip].backlog
}

// Check returns true if we have any kind of interrest in the address: either we already know it
// (and so an update would be good), or we're trying to resolve it.
func (cache *neighborCache) check(ip netip.Addr) bool {
	if cache.isLoop {
		return false
	}
	return cache.mappings[ip].timer != 0
}

// Associates the given IP address to the given MAC address, unless an identical association
// already exists. Returns a pointer to the retained value. This cannonicalization reduces GC
// pressure by not forcing a copy of the given address to escape to the heap unnecessarily.
// The second return value is true if an entry was added or changed.
func (cache *neighborCache) put(ip netip.Addr, mac [6]byte) (*[6]byte, bool) {
	if cache.isLoop {
		return &zeroMacAddr, false
	}
	entry := cache.mappings[ip]
	if entry.state == None {
		entry.backlog = make(chan *router.Packet, neighborMaxBacklog)
	}
	entry.timer = neighborTTL
	entry.state = Reachable
	isChange := false
	if entry.mac == nil || *entry.mac != mac {
		entry.mac = &mac
		isChange = true
	}
	cache.mappings[ip] = entry
	return entry.mac, isChange
}

// tick updates the timer of each entry. Itdeletes entries that have been in the cache for too
// long. Resolved entries live for neighborTTL seconds. Once their time is below neighborTTR a
// resolution is attempted if there is a backlog. Unresolved entries live for no more than
// neighborTTR seconds. When an entry is used while its time is below TTR, a single refresh
// is attempted.
func (cache *neighborCache) tick() {
	cache.Lock()
	for k, entry := range cache.mappings {
		if entry.timer == 0 {
			// Completely stale. Throw away.
			delete(cache.mappings, k)
			close(entry.backlog)
			for p := range entry.backlog {
				cache.pool.Put(p)
			}
			continue
		}
		entry.timer--
		switch entry.state {
		case None:
			// WTF? they're never inserted in the map like that.
			continue
		case Incomplete, Probe:
			// We do need the address resolved.
			cache.seekNeighbor(&k)
		case Stale:
			// Not in active use, so don't refresh.
		case Reachable:
			if entry.timer < neighborTTR {
				entry.state = Stale
			}
		default:
			panic("Illegal entry state")
		}
		cache.mappings[k] = entry
	}
	cache.Unlock()
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
	// Ticker task
	go func() {
		defer log.HandlePanic()
		for cache.running.Load() {
			cache.tick()
			time.Sleep(neighborTick)
		}
		close(cache.tickerDone)
	}()
}

func (cache *neighborCache) stop() {
	wasRunning := cache.running.Swap(false)
	if cache.isLoop {
		return
	}
	if wasRunning {
		<-cache.tickerDone
	}
}

func newNeighborCache(
	name string,
	localMAC net.HardwareAddr,
	localIP netip.Addr,
	egressQ chan *router.Packet,
) *neighborCache {
	return &neighborCache{
		name:       name,
		localMAC:   localMAC,
		localIP:    localIP,
		mappings:   make(map[netip.Addr]neighbor),
		egressQ:    egressQ,
		tickerDone: make(chan struct{}),
		is4:        localIP.Is4(),
		isLoop:     ([6]byte(localMAC) == zeroMacAddr),
	}
}

// packNeighborReq builds an ARP or NDP request into the given packet.
// It does not need to refer to the cache but there's no more relevant place to put this.
func packNeighborReq(
	p *router.Packet,
	localIP *netip.Addr,
	localMAC net.HardwareAddr,
	remoteIP *netip.Addr,
	v4 bool,
) {
	serBuf := router.NewSerializeProxyStart(p.RawPacket, 128)
	var err error

	// TODO(jiceatscion): use a canned packet?
	if v4 {
		ethernet := layers.Ethernet{
			SrcMAC:       localMAC,
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeARP,
		}
		arp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			HwAddressSize:     6,
			Protocol:          layers.EthernetTypeIPv4,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   localMAC,
			SourceProtAddress: localIP.AsSlice(),
			DstHwAddress:      zeroMacAddr[:],
			DstProtAddress:    remoteIP.AsSlice(),
		}
		err = gopacket.SerializeLayers(&serBuf, seropts, &ethernet, &arp)
	} else {
		var typ uint8
		var mcAddr []byte
		var dstMAC []byte

		// We can do announcements too. The intent is conveyed using the IPv4 convention.
		if *localIP == *remoteIP {
			mcAddr = netip.IPv6LinkLocalAllNodes().AsSlice()
			typ = layers.ICMPv6TypeNeighborAdvertisement
			dstMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		} else {
			mcAddr = remoteIP.AsSlice()
			copy(mcAddr[0:13], ndpMcastPrefix)
			typ = layers.ICMPv6TypeNeighborSolicitation
			dstMAC = net.HardwareAddr{0x33, 0x33, mcAddr[12], mcAddr[13], mcAddr[14], mcAddr[15]}
		}
		ethernet := layers.Ethernet{
			SrcMAC:       localMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv6,
		}
		ipv6 := layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   255,
			SrcIP:      localIP.AsSlice(),
			DstIP:      mcAddr,
		}
		icmp6 := layers.ICMPv6{
			TypeCode: layers.CreateICMPv6TypeCode(typ, 0),
		}
		request := layers.ICMPv6NeighborSolicitation{
			TargetAddress: remoteIP.AsSlice(),
			Options: layers.ICMPv6Options{
				layers.ICMPv6Option{Type: layers.ICMPv6OptSourceAddress, Data: localMAC},
			},
		}
		_ = icmp6.SetNetworkLayerForChecksum(&ipv6)
		err = gopacket.SerializeLayers(&serBuf, seropts, &ethernet, &ipv6, &icmp6, &request)
	}
	if err != nil {
		// The only possible reason for this is in the few lines above.
		panic("cannot serialize neighbor response")
	}
	p.RawPacket = serBuf.Bytes()
}

// packNeighborResp builds a an ARP/NDP response into the given packet.
// It does not need to refer to the cache but there's no more relevant place to put this.
func packNeighborResp(
	p *router.Packet,
	localIP *netip.Addr, // The question
	localMAC net.HardwareAddr, // The answer
	remoteIP *netip.Addr, // The requestant
	remoteMAC net.HardwareAddr, // Ditto
	is4 bool,
) {
	serBuf := router.NewSerializeProxyStart(p.RawPacket, 128)
	var err error

	if is4 {
		ethernet := layers.Ethernet{
			SrcMAC:       localMAC,
			DstMAC:       remoteMAC,
			EthernetType: layers.EthernetTypeARP,
		}
		arp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			HwAddressSize:     6,
			Protocol:          layers.EthernetTypeIPv4,
			ProtAddressSize:   4,
			Operation:         layers.ARPReply,
			SourceHwAddress:   localMAC,
			SourceProtAddress: localIP.AsSlice(),
			DstHwAddress:      remoteMAC,
			DstProtAddress:    remoteIP.AsSlice(),
		}
		err = gopacket.SerializeLayers(&serBuf, seropts, &ethernet, &arp)
	} else {
		ethernet := layers.Ethernet{
			SrcMAC:       localMAC,
			DstMAC:       remoteMAC,
			EthernetType: layers.EthernetTypeIPv6,
		}
		ipv6 := layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   255,
			SrcIP:      localIP.AsSlice(),
			DstIP:      remoteIP.AsSlice(),
		}
		icmp6 := layers.ICMPv6{
			TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
		}
		response := layers.ICMPv6NeighborAdvertisement{
			Flags:         0x60, // Sollicited | Override.
			TargetAddress: localIP.AsSlice(),
			Options: layers.ICMPv6Options{
				layers.ICMPv6Option{Type: layers.ICMPv6OptTargetAddress, Data: localMAC},
			},
		}
		_ = icmp6.SetNetworkLayerForChecksum(&ipv6)
		err = gopacket.SerializeLayers(&serBuf, seropts, &ethernet, &ipv6, &icmp6, &response)
	}
	if err != nil {
		// The only possible reason for this is in the few lines above.
		panic("cannot serialize neighbor response")
	}
	p.RawPacket = serBuf.Bytes()
}
