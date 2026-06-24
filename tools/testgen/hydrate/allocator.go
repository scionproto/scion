// Copyright 2026 Anapaya Systems
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

package hydrate

import (
	"net/netip"
	"sort"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/tools/testgen/topo"
)

// Allocator assigns the underlay networks that the topology leaves implicit.
// Implementations must be deterministic: the same topology must always yield
// the same allocation.
type Allocator interface {
	// AS returns the internal network for an AS. Host (service) addresses are
	// carved from this subnet by the hydrator. The underlay selects the address
	// family.
	AS(ia addr.IA, u topo.UnderlayType) (ASAlloc, error)
	// Link returns the point-to-point underlay network for the link at the
	// given index in the topology's link list, together with the two endpoint
	// addresses (A first, then B).
	Link(index int, l topo.Link) (LinkAlloc, error)
}

// ASAlloc is the allocation for a single AS.
type ASAlloc struct {
	Subnet netip.Prefix
}

// LinkAlloc is the allocation for a single inter-AS link.
type LinkAlloc struct {
	Subnet netip.Prefix
	A      netip.Addr
	B      netip.Addr
}

// ClabConfig configures the default containerlab-oriented allocator.
type ClabConfig struct {
	// NetworkV4 is the base IPv4 network. AS-internal /24s are carved from its
	// first half and inter-AS link /30s from its second half. Must be at most a
	// /16 prefix wide (e.g. 10.0.0.0/8).
	NetworkV4 netip.Prefix
	// NetworkV6 is the base IPv6 network. AS-internal /64s and link /126s are
	// carved from it.
	NetworkV6 netip.Prefix
}

// DefaultClabConfig returns the default allocator configuration.
func DefaultClabConfig() ClabConfig {
	return ClabConfig{
		NetworkV4: netip.MustParsePrefix("10.0.0.0/8"),
		NetworkV6: netip.MustParsePrefix("fd00:f00d:cafe::/48"),
	}
}

// clabAllocator is the default containerlab-friendly allocator. It hands out
// one /24 (or /64) per AS and one /30 (or /126) per link, drawn from disjoint
// regions of the configured base networks.
type clabAllocator struct {
	cfg     ClabConfig
	asIndex map[addr.IA]int
}

// NewClabAllocator builds the default allocator for the given topology. The AS
// ordering (and therefore the allocation) is derived from the sorted ISD-AS
// list so runs are byte-stable.
func NewClabAllocator(t *topo.Topo, cfg ClabConfig) Allocator {
	ias := make([]addr.IA, 0, len(t.ASes))
	for ia := range t.ASes {
		ias = append(ias, ia)
	}
	sort.Slice(ias, func(i, j int) bool { return ias[i].String() < ias[j].String() })
	idx := make(map[addr.IA]int, len(ias))
	for i, ia := range ias {
		idx[ia] = i
	}
	return &clabAllocator{cfg: cfg, asIndex: idx}
}

func (a *clabAllocator) AS(ia addr.IA, u topo.UnderlayType) (ASAlloc, error) {
	i, ok := a.asIndex[ia]
	if !ok {
		return ASAlloc{}, serrors.New("AS not known to allocator", "as", ia)
	}
	if u.IsIPv6() {
		// fd00:f00d:cafe:<i>::/64 — the subnet id is the 4th hextet.
		base := withHextet3(a.cfg.NetworkV6.Addr(), uint16(i))
		return ASAlloc{Subnet: netip.PrefixFrom(base, 64)}, nil
	}
	// First region of the v4 space, one /24 per AS: base + i*256.
	base := offset(a.cfg.NetworkV4.Addr(), uint64(i)*256)
	return ASAlloc{Subnet: netip.PrefixFrom(base, 24)}, nil
}

func (a *clabAllocator) Link(index int, l topo.Link) (LinkAlloc, error) {
	if l.Underlay.IsIPv6() {
		// Link region of the v6 space (4th hextet >= 0x8000), one /126 per link.
		region := withHextet3(a.cfg.NetworkV6.Addr(), 0x8000)
		base := offset(region, uint64(index)*4)
		return LinkAlloc{
			Subnet: netip.PrefixFrom(base, 126),
			A:      offset(base, 1),
			B:      offset(base, 2),
		}, nil
	}
	// Second half of the v4 space (offset 8M ≈ 10.128.0.0 for a /8), one /30
	// per link.
	region := offset(a.cfg.NetworkV4.Addr(), uint64(8)<<20)
	base := offset(region, uint64(index)*4)
	return LinkAlloc{
		Subnet: netip.PrefixFrom(base, 30),
		A:      offset(base, 1),
		B:      offset(base, 2),
	}, nil
}

// withHextet3 returns base (an IPv6 address) with its 4th hextet (bits 64-79)
// set to id and the host portion (low 64 bits) zeroed. It is used to pick a
// distinct /64 or link region within a /48 base network.
func withHextet3(base netip.Addr, id uint16) netip.Addr {
	b := base.As16()
	b[6] = byte(id >> 8)
	b[7] = byte(id)
	for i := 8; i < 16; i++ {
		b[i] = 0
	}
	return netip.AddrFrom16(b)
}

// offset returns base + n, treating the address as a big-endian integer. It
// works for both IPv4 and IPv6 addresses.
func offset(base netip.Addr, n uint64) netip.Addr {
	if base.Is4() {
		b := base.As4()
		v := uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
		v += n
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	b := base.As16()
	// Add n to the low 64 bits with carry into the high bits.
	lo := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
	hi := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	newLo := lo + n
	if newLo < lo {
		hi++
	}
	var out [16]byte
	for i := 0; i < 8; i++ {
		out[7-i] = byte(hi >> (8 * i))
		out[15-i] = byte(newLo >> (8 * i))
	}
	return netip.AddrFrom16(out)
}
