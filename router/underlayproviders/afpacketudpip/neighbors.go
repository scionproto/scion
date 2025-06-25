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

// ARP cache parameters. The longuish TTL is because I suspect that linux rate limits responses,
// so, we have to resolve stuff other than a SCION router not too often. This is simplistic
// compared to Linux's arp life-cycle. Like Linux, we consider entries only when they get used;
// otherwise we just decrease their TTL.
const (
	neighborTick = 500 * time.Millisecond // Cache clock period.
	neighborTTL  = 1200                   // Time to live of resolved entry (in ticks).
	neighborTTR  = 2                      // TTL threshold for resolution (in ticks).
)

// FF02:0000:0000:0000:0000:0001:FF00:0000/104
var ndpMcastPrefix = []byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1, 0xff}
var zeroMacAddr = [6]byte{0, 0, 0, 0, 0, 0}
var dummyMacAddr = [6]byte{2, 0, 0, 0, 0, 1}

type neighbor struct {
	mac *[6]byte
	// timer keeps track of the time that the entry has been resolved or pending:
	timer int
}

// neighborCache is a cache of IP address to MAC address mapping. It is not automatically
// re-entrant: you must use lock() and unlock() explicitly. The reason is that we have two different
// usage patterns; one of which needs to manipulate another object in the same critical section.
// There is a builtin entry expiration ticker. Calling start() will activate it and stop() will
// deactivate it. While active, the ticker deletes entries that have been in the cache for too
// long. Resolved entries live for neighborTTL seconds. Once their time is below neighborTTR a
// resolution is triggered in case of use. Unresolved entries live for no more than neighborTTR
// secons.
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

	if ip.Is4() && ip.IsLoopback() {
		// This cannot be reliably resolved (linux will not respond to requests), and any MAC
		// address will do. Try and use zero; that's what Linux pretends it is when it has to
		// pretend.
		return &zeroMacAddr, true
	}

	entry := cache.mappings[ip]
	if entry.timer != 0 {
		// Already resolved or being resolved. May be we have a good address, or a stale one, or
		// nothing at all. Nothing else to do.
		return entry.mac, true
	}
	// Unknown or just got stale. Trigger a new resolution. In the meantime, we can still use the
	// stale address if there is one.
	entry.timer = neighborTTR
	cache.mappings[ip] = entry
	return entry.mac, false
}

// Check returns true if we have any kind of interrest in the address: either we already know it
// (and so an update would be good), or we're trying to resolve it.
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
	cache.mappings[ip] = neighbor{oldEntry.mac, neighborTTL} // Just refresh the TTL
	return oldEntry.mac, false
}

// tick updates the timer of each entry.
func (cache *neighborCache) tick() {
	cache.Lock()
	for k, n := range cache.mappings {
		if n.timer == 0 {
			// Completely stale. Throw away.
			delete(cache.mappings, k)
			continue
		}
		n.timer--
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
			time.Sleep(neighborTick)
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
