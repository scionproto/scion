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

package clab

import (
	"io"
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/scionproto/scion/testing/clab/testgen/hydrate"
	"github.com/scionproto/scion/testing/clab/testgen/out"
	"github.com/scionproto/scion/testing/clab/testgen/topo"
)

func hydrateTopo(t *testing.T, raw string) *hydrate.Network {
	t.Helper()
	parsed, err := topo.Parse([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, parsed.Validate())
	n, err := hydrate.Hydrate(parsed, hydrate.NewClabAllocator(parsed, hydrate.DefaultClabConfig()))
	require.NoError(t, err)
	return n
}

func TestGenerate(t *testing.T) {
	t.Parallel()
	n := hydrateTopo(t, `
ASes:
  "1-ff00:0:110": {core: true, voting: true, authoritative: true, issuing: true}
  "1-ff00:0:111": {cert_issuer: 1-ff00:0:110}
links:
  - {a: "1-ff00:0:110#1", b: "1-ff00:0:111#41", linkAtoB: CHILD}
`)
	dir := out.New(t.TempDir(), false)
	opts := Options{
		LabName: "scion2",
		MgmtV4:  netip.MustParsePrefix("10.0.0.0/16"),
	}
	require.NoError(t, Generate(n, dir, opts, io.Discard))

	raw, err := os.ReadFile(dir.Clab("scion2"))
	require.NoError(t, err)
	var clab clabTopology
	require.NoError(t, yaml.Unmarshal(raw, &clab))

	assert.Equal(t, "scion2", clab.Name)
	assert.Equal(t, "scion2-mgmt", clab.Mgmt.Network)
	assert.Equal(t, "10.0.0.0/16", clab.Mgmt.IPv4Subnet)
	// Two single-host ASes -> two nodes, one inter-AS link.
	require.Len(t, clab.Topology.Nodes, 2)
	require.Len(t, clab.Topology.Links, 1)
	assert.ElementsMatch(t,
		[]string{"1-ff00_0_110-host-1:eth1", "1-ff00_0_111-host-1:eth1"},
		clab.Topology.Links[0].Endpoints,
	)

	n110 := clab.Topology.Nodes["1-ff00_0_110-host-1"]
	require.NotNil(t, n110)
	assert.NotEmpty(t, n110.MgmtIPv4)
	assert.Contains(t, n110.Binds, "ASff00_0_110/host-1:/etc/scion:rw")
}

func TestGenerateMultiHost(t *testing.T) {
	t.Parallel()
	// Tags -A and -B create extra hosts -> extra nodes in the same AS, joined
	// via the management network (no extra links needed).
	n := hydrateTopo(t, `
ASes:
  "1-ff00:0:110": {core: true, voting: true, authoritative: true, issuing: true}
  "1-ff00:0:111": {cert_issuer: 1-ff00:0:110}
  "1-ff00:0:112": {cert_issuer: 1-ff00:0:110}
links:
  - {a: "1-ff00:0:110-A#1", b: "1-ff00:0:111#1", linkAtoB: CHILD}
  - {a: "1-ff00:0:110-B#2", b: "1-ff00:0:112#1", linkAtoB: CHILD}
`)
	dir := out.New(t.TempDir(), false)
	err := Generate(n, dir, Options{
		LabName: "m",
		MgmtV4:  netip.MustParsePrefix("10.0.0.0/16")},
		io.Discard,
	)
	require.NoError(t, err)

	raw, err := os.ReadFile(dir.Clab("m"))
	require.NoError(t, err)
	var clab clabTopology
	require.NoError(t, yaml.Unmarshal(raw, &clab))

	assert.Contains(t, clab.Topology.Nodes, "1-ff00_0_110-host-A")
	assert.Contains(t, clab.Topology.Nodes, "1-ff00_0_110-host-B")
	// Two inter-AS links, no intra-AS links (mgmt network handles that).
	assert.Len(t, clab.Topology.Links, 2)
}

func TestGenerateHostLinks(t *testing.T) {
	t.Parallel()
	parsed, err := topo.Parse([]byte(`
ASes:
  "1-ff00:0:110": {core: true, voting: true, authoritative: true, issuing: true}
  "1-ff00:0:111": {cert_issuer: 1-ff00:0:110, underlay: UDP/IPv6}
links:
  - {a: "1-ff00:0:110#1", b: "1-ff00:0:111#41", linkAtoB: CHILD}
`))
	require.NoError(t, err)
	require.NoError(t, parsed.Validate())
	alloc := hydrate.NewClabAllocator(parsed, hydrate.DefaultClabConfig())
	n, err := hydrate.Hydrate(parsed, alloc)
	require.NoError(t, err)
	require.NoError(t, hydrate.AddHostLinks(n, alloc))

	dir := out.New(t.TempDir(), false)
	require.NoError(t, Generate(n, dir, Options{LabName: "hl"}, io.Discard))
	raw, err := os.ReadFile(dir.Clab("hl"))
	require.NoError(t, err)
	var clab clabTopology
	require.NoError(t, yaml.Unmarshal(raw, &clab))

	// One inter-AS link plus one host link per AS.
	require.Len(t, clab.Topology.Links, 3)
	assert.Contains(t, clab.Topology.Links,
		link{Endpoints: []string{"1-ff00_0_110-host-1:eth2", "host:1-ff00_0_110"}})
	assert.Contains(t, clab.Topology.Links,
		link{Endpoints: []string{"1-ff00_0_111-host-1:eth2", "host:1-ff00_0_111"}})

	n110 := clab.Topology.Nodes["1-ff00_0_110-host-1"]
	require.NotNil(t, n110.Stages)
	require.NotNil(t, n110.Stages.CreateLinks)
	assert.Equal(t, []stageExec{
		{
			Command: "ip addr replace 10.192.0.2/30 dev 1-ff00_0_110",
			Target:  "host", Phase: "on-exit",
		},
		{
			Command: "ip route replace 10.0.1.2/32 via 10.192.0.1 dev 1-ff00_0_110",
			Target:  "host", Phase: "on-exit",
		},
	}, n110.Stages.CreateLinks.Exec)

	n111 := clab.Topology.Nodes["1-ff00_0_111-host-1"]
	require.NotNil(t, n111.Stages)
	assert.Equal(t, []stageExec{
		{
			Command: "ip -6 addr replace fd00:f00d:cafe:9000::6/126 dev 1-ff00_0_111 nodad",
			Target:  "host", Phase: "on-exit",
		},
		{
			Command: "ip -6 route replace fd00:f00d:cafe::202/128 via fd00:f00d:cafe:9000::5" +
				" dev 1-ff00_0_111",
			Target: "host", Phase: "on-exit",
		},
	}, n111.Stages.CreateLinks.Exec)
}
