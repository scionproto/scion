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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
)

func TestAddGateways(t *testing.T) {
	t.Parallel()
	parsed := mustTopo(t, tiny)
	alloc := NewClabAllocator(parsed, DefaultClabConfig())
	n, err := Hydrate(parsed, alloc)
	require.NoError(t, err)
	require.NoError(t, AddGateways(n, alloc))

	as110 := findAS(n, "1-ff00:0:110")
	gw := as110.Gateway
	require.NotNil(t, gw)
	assert.True(t, as110.Hosts[0].Gateway)
	host := as110.Hosts[0].Addr
	assert.Equal(t, addr.MustParseIA("1-ff00:0:110"), gw.IA)
	assert.Equal(t, "gw1-ff00_0_110-1", gw.ID)
	assert.Equal(t, "host-1", gw.Host)
	assert.Equal(t, netip.AddrPortFrom(host, 30256), gw.CtrlAddr)
	assert.Equal(t, netip.AddrPortFrom(host, 30056), gw.DataAddr)
	assert.Equal(t, netip.AddrPortFrom(host, 30856), gw.ProbeAddr)
	assert.Equal(t, netip.AddrPortFrom(host, 41400), gw.APIAddr)
	assert.Equal(t, netip.MustParsePrefix("172.16.0.0/24"), gw.Prefix)
	assert.Equal(t, netip.MustParseAddr("172.16.0.1"), gw.Addr)

	// 112 is an IPv6 AS: the gateway listens on the IPv6 host address, but
	// the prefix behind it is IPv4, from the next /24.
	gw112 := findAS(n, "1-ff00:0:112").Gateway
	require.NotNil(t, gw112)
	assert.True(t, gw112.CtrlAddr.Addr().Is6())
	assert.Equal(t, netip.MustParsePrefix("172.16.2.0/24"), gw112.Prefix)

	// Every gateway knows the gateways of all other ASes.
	var remotes []addr.IA
	for _, r := range gw.Remotes {
		remotes = append(remotes, r.IA)
	}
	assert.Equal(t, []addr.IA{
		addr.MustParseIA("1-ff00:0:111"),
		addr.MustParseIA("1-ff00:0:112"),
	}, remotes)

	// The allocation record lists every gateway.
	recs := n.Allocations().Gateways
	require.Len(t, recs, 3)
	assert.Equal(t, GatewayRecord{
		ISDAS:  "1-ff00:0:110",
		ID:     "gw1-ff00_0_110-1",
		Host:   "host-1",
		Prefix: "172.16.0.0/24",
		Addr:   "172.16.0.1",
	}, recs[0])
}

func TestGatewayAllocNetworkTooSmall(t *testing.T) {
	t.Parallel()
	parsed := mustTopo(t, tiny)
	cfg := DefaultClabConfig()
	// Room for a single /24 only, but the topology has three ASes.
	cfg.GatewayV4 = netip.MustParsePrefix("172.16.0.0/24")
	alloc := NewClabAllocator(parsed, cfg)
	n, err := Hydrate(parsed, alloc)
	require.NoError(t, err)
	assert.Error(t, AddGateways(n, alloc))
}

func TestGatewayAllocNetworkOverlap(t *testing.T) {
	t.Parallel()
	for name, gw := range map[string]string{
		"base network":      "10.0.0.0/16",
		"docker0":           "172.17.0.0/16",
		"containerlab mgmt": "172.20.20.0/24",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			parsed := mustTopo(t, tiny)
			cfg := DefaultClabConfig()
			cfg.GatewayV4 = netip.MustParsePrefix(gw)
			alloc := NewClabAllocator(parsed, cfg)
			n, err := Hydrate(parsed, alloc)
			require.NoError(t, err)
			assert.Error(t, AddGateways(n, alloc))
		})
	}
}
