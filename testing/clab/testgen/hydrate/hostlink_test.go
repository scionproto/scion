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

func TestAddHostLinks(t *testing.T) {
	t.Parallel()
	parsed := mustTopo(t, tiny)
	alloc := NewClabAllocator(parsed, DefaultClabConfig())
	n, err := Hydrate(parsed, alloc)
	require.NoError(t, err)
	require.NoError(t, AddHostLinks(n, alloc))

	// 110 (IPv4 AS): two inter-AS interfaces on host-1 -> host link is eth3.
	hl := findAS(n, "1-ff00:0:110").Hosts[0].HostLink
	require.NotNil(t, hl)
	assert.Equal(t, HostLink{
		EthName:   "eth3",
		HostIface: "1-ff00_0_110",
		Net:       netip.MustParsePrefix("10.192.0.0/30"),
		NodeAddr:  netip.MustParseAddr("10.192.0.1"),
		HostAddr:  netip.MustParseAddr("10.192.0.2"),
	}, *hl)

	// 111 (IPv4 AS, second in order): one interface -> eth2, next /30.
	hl = findAS(n, "1-ff00:0:111").Hosts[0].HostLink
	require.NotNil(t, hl)
	assert.Equal(t, "eth2", hl.EthName)
	assert.Equal(t, netip.MustParsePrefix("10.192.0.4/30"), hl.Net)

	// 112 (IPv6 AS): the host link follows the AS underlay family.
	hl = findAS(n, "1-ff00:0:112").Hosts[0].HostLink
	require.NotNil(t, hl)
	assert.Equal(t, netip.MustParsePrefix("fd00:f00d:cafe:9000::8/126"), hl.Net)
	assert.Equal(t, netip.MustParseAddr("fd00:f00d:cafe:9000::9"), hl.NodeAddr)
	assert.Equal(t, netip.MustParseAddr("fd00:f00d:cafe:9000::a"), hl.HostAddr)

	// The allocation record lists every host link.
	assert.Len(t, n.Allocations().HostLinks, 3)
}

func TestHostIfaceName(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "1-ff00_0_110", hostIfaceName(addr.MustParseIA("1-ff00:0:110"), 0))
	// Too long for a Linux interface name -> index-based fallback.
	assert.Equal(t, "scion-as7", hostIfaceName(addr.MustParseIA("65535-ffff:ffff:ffff"), 7))
}
