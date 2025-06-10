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

const (
	neighborTick = 1 * time.Second // Cache clock period.
	neighborTTL  = 20              // Time until a resolved entry is stale.
	neighborTTR  = 3               // Time until giving up on an unresolved entry.
)

type neighbor struct {
	mac *[6]byte
	// timer keeps track of the time that the entry has been resolved or pending:
	timer int
}

// neighborCache is a cache of IP address to MAC address mapping. It is not automatically
// re-entrant: you must use lock() and unlock() explicitly. The reason is that we have two different
// usage patterns; one of which needs to manipulate another object in the same critical section.
// There is a builtin entry expiration ticker. Calling start() will activate it and stop()
// will deactivate it. While active, the ticker deletes entries that have been in the cache for too
// long. Pending entries live for neighborTTR seconds and resolved entries live for neighborTTL
// seconds.
type neighborCache struct {
	sync.Mutex
	mappings   map[netip.Addr]neighbor
	running    atomic.Bool
	tickerDone chan struct{}
}

// Lookup returns the mac address associated with the given IP, or nil if not known, and whether an
// entry already existed. A new (pending) entry is created if none existed. A resolution should be
// triggered if the entry did not exist. This is optional, but the pending entry will exist for as
// long as specified by the TTR.
func (cache *neighborCache) get(ip netip.Addr) (*[6]byte, bool) {
	entry := cache.mappings[ip]
	if entry.timer > 0 {
		// Valid.
		return entry.mac, true
	}
	if entry.timer < 0 {
		// Already pending
		return nil, true
	}
	// Unknown. Must trigger a resolution.
	cache.mappings[ip] = neighbor{nil, -neighborTTR}
	return nil, false
}

func (cache *neighborCache) check(ip netip.Addr) bool {
	return cache.mappings[ip].timer != 0
}

// Associates the given IP address to the given MAC address, unless an identical association
// already exists. Returns a pointer to the retained value. This cannonicalization reduces GC
// pressure by not forcing a copy of the given address to escape to the heap unnecessarily.
// The second return value is true if an entry was added or changed.
func (cache *neighborCache) put(ip netip.Addr, mac [6]byte) (*[6]byte, bool) {
	oldEntry := cache.mappings[ip]
	if oldEntry.mac == nil || *oldEntry.mac != mac {
		newMAC := &mac
		cache.mappings[ip] = neighbor{newMAC, neighborTTL}
		return newMAC, true
	}
	return oldEntry.mac, false
}

// tick updates the timer of each entry.
func (cache *neighborCache) tick() {
	cache.Lock()
	for k, n := range cache.mappings {
		if n.timer == 0 {
			// Stale. Throw away.
			delete(cache.mappings, k)
			continue
		}
		if n.timer > 0 {
			n.timer--
		} else {
			n.timer++
		}
		cache.mappings[k] = n
	}
	cache.Unlock()
}

func (cache *neighborCache) start() {
	wasRunning := cache.running.Swap(true)
	if wasRunning {
		return
	}

	// Ticker task
	go func() {
		defer log.HandlePanic()
		for cache.running.Load() {
			cache.tick()
		}
		close(cache.tickerDone)
	}()
}

func (cache *neighborCache) stop() {
	wasRunning := cache.running.Swap(false)
	if wasRunning {
		<-cache.tickerDone
	}
}

func newNeighborCache() *neighborCache {
	return &neighborCache{mappings: make(map[netip.Addr]neighbor)}
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
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
			DstProtAddress:    remoteIP.AsSlice(),
		}
		err = gopacket.SerializeLayers(&serBuf, seropts, &ethernet, &arp)
	} else {
		var code layers.ICMPv6TypeCode
		var mcAddr []byte

		// We can do announcements too. The intent is conveyed using the IPv4 convention.
		if *localIP == *remoteIP {
			mcAddr = netip.IPv6LinkLocalAllNodes().AsSlice()
			code = layers.ICMPv6TypeNeighborAdvertisement
		} else {
			mcAddr = remoteIP.AsSlice()
			code = layers.ICMPv6TypeNeighborSolicitation
		}
		copy(mcAddr, ndpMcastPrefix)
		ethernet := layers.Ethernet{
			SrcMAC:       localMAC,
			DstMAC:       net.HardwareAddr{0x33, 0x33, 0xff, mcAddr[13], mcAddr[14], mcAddr[15]},
			EthernetType: layers.EthernetTypeIPv6,
		}
		ipv6 := layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   64,
			SrcIP:      localIP.AsSlice(),
			DstIP:      mcAddr,
		}
		icmp6 := layers.ICMPv6{
			TypeCode: code,
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
			HopLimit:   64,
			SrcIP:      localIP.AsSlice(),
			DstIP:      remoteIP.AsSlice(),
		}
		icmp6 := layers.ICMPv6{
			TypeCode: layers.ICMPv6TypeNeighborAdvertisement,
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
