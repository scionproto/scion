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

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/testing/clab/testgen/hydrate"
	"github.com/scionproto/scion/testing/clab/testgen/topo"
)

func hydrateTiny(t *testing.T) *hydrate.Network {
	t.Helper()
	parsed, err := topo.Parse([]byte(`
ASes:
  "1-ff00:0:110": {core: true, voting: true, authoritative: true, issuing: true, mtu: 1400}
  "1-ff00:0:111": {cert_issuer: 1-ff00:0:110}
links:
  - {a: "1-ff00:0:110#1", b: "1-ff00:0:111#41", linkAtoB: CHILD, mtu: 1280}
`))
	require.NoError(t, err)
	require.NoError(t, parsed.Validate())
	n, err := hydrate.Hydrate(parsed, hydrate.NewClabAllocator(parsed, hydrate.DefaultClabConfig()))
	require.NoError(t, err)
	return n
}

func as(t *testing.T, n *hydrate.Network, ia string) *hydrate.AS {
	t.Helper()
	want := addr.MustParseIA(ia)
	for _, a := range n.ASes {
		if a.IA == want {
			return a
		}
	}
	t.Fatalf("AS %s not found", ia)
	return nil
}

func TestHostConfigBorderRouterHost(t *testing.T) {
	t.Parallel()
	n := hydrateTiny(t)
	a := as(t, n, "1-ff00:0:110")
	cfg := HostConfig(a, a.Hosts[0])

	require.Len(t, cfg.SCION.ASes, 1)
	got := cfg.SCION.ASes[0]
	assert.Equal(t, a.IA, got.ISDAS)
	assert.True(t, got.Core)
	// host-1 runs all three elements.
	require.NotNil(t, got.Router)
	require.NotNil(t, got.Control)
	require.NotNil(t, got.Daemon)
	assert.True(t, got.Control.Issuing)
	// Neighbor 111 is reachable as a CHILD.
	require.Len(t, got.Neighbors, 1)
	assert.Equal(t, addr.MustParseIA("1-ff00:0:111"), got.Neighbors[0].ISDAS)
	// Interface section binds the inter-AS data-plane link (eth1+); the mgmt
	// interface (eth0) is configured by containerlab.
	require.NotEmpty(t, cfg.Interfaces.Ethernets)
	assert.Equal(t, "eth1", cfg.Interfaces.Ethernets[0].Name)
}

func TestTopologyJSON(t *testing.T) {
	t.Parallel()
	n := hydrateTiny(t)
	a := as(t, n, "1-ff00:0:110")
	top := Topology(a)

	assert.Equal(t, "1-ff00:0:110", top.IA)
	assert.Equal(t, 1400, top.MTU)
	require.Len(t, top.BorderRouters, 1)
	require.Len(t, top.ControlService, 1)
	require.Len(t, top.DiscoveryService, 1)
	br := top.BorderRouters[a.BorderRouters[0].ID]
	require.NotNil(t, br)
	require.Len(t, br.Interfaces, 1)
	intf := br.Interfaces[1] // 110's local interface id
	require.NotNil(t, intf)
	assert.Equal(t, "1-ff00:0:111", intf.IA)
	assert.Equal(t, "CHILD", intf.LinkTo)
	assert.EqualValues(t, 41, intf.RemoteIfID)
}
