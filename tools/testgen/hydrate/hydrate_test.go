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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/tools/testgen/topo"
)

func mustTopo(t *testing.T, raw string) *topo.Topo {
	t.Helper()
	parsed, err := topo.Parse([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, parsed.Validate())
	return parsed
}

const tiny = `
ASes:
  "1-ff00:0:110": {core: true, voting: true, authoritative: true, issuing: true, mtu: 1400}
  "1-ff00:0:111": {cert_issuer: 1-ff00:0:110}
  "1-ff00:0:112": {cert_issuer: 1-ff00:0:110, underlay: UDP/IPv6}
links:
  - {a: "1-ff00:0:110#1", b: "1-ff00:0:111#41", linkAtoB: CHILD, mtu: 1280}
  - {a: "1-ff00:0:110#2", b: "1-ff00:0:112#1", linkAtoB: CHILD, underlay: UDP/IPv6}
`

func hydrateTiny(t *testing.T) *Network {
	t.Helper()
	parsed := mustTopo(t, tiny)
	n, err := Hydrate(parsed, NewClabAllocator(parsed, DefaultClabConfig()))
	require.NoError(t, err)
	return n
}

func TestBorderRouterGrouping(t *testing.T) {
	// Untagged interfaces share a single border router; AS 110 has two
	// untagged links and so a single border router -> a single host.
	n := hydrateTiny(t)
	as110 := findAS(n, "1-ff00:0:110")
	require.NotNil(t, as110)
	require.Len(t, as110.BorderRouters, 1)
	assert.Len(t, as110.BorderRouters[0].Interfaces, 2)
	require.Len(t, as110.Hosts, 1)
	// The single host is named host-1 and runs all three elements.
	assert.Equal(t, "host-1", as110.Hosts[0].Name)
	assert.True(t, as110.Hosts[0].Control)
	assert.True(t, as110.Hosts[0].Daemon)
	assert.NotNil(t, as110.Hosts[0].BorderRouter)
}

func TestTaggedBorderRouterGrouping(t *testing.T) {
	parsed := mustTopo(t, `
ASes:
  "1-ff00:0:110": {core: true, voting: true, authoritative: true, issuing: true}
  "1-ff00:0:111": {cert_issuer: 1-ff00:0:110}
  "1-ff00:0:112": {cert_issuer: 1-ff00:0:110}
  "1-ff00:0:113": {cert_issuer: 1-ff00:0:110}
links:
  - {a: "1-ff00:0:110-A#1", b: "1-ff00:0:111#1", linkAtoB: CHILD}
  - {a: "1-ff00:0:110-A#2", b: "1-ff00:0:112#1", linkAtoB: CHILD}
  - {a: "1-ff00:0:110-B#3", b: "1-ff00:0:113#1", linkAtoB: CHILD}
`)
	n, err := Hydrate(parsed, NewClabAllocator(parsed, DefaultClabConfig()))
	require.NoError(t, err)
	as110 := findAS(n, "1-ff00:0:110")
	// Tags A and B -> two border routers, two hosts named after the tags.
	require.Len(t, as110.BorderRouters, 2)
	require.Len(t, as110.Hosts, 2)
	names := []string{as110.Hosts[0].Name, as110.Hosts[1].Name}
	assert.ElementsMatch(t, []string{"host-A", "host-B"}, names)
	// With no untagged group, control + daemon land on the first host.
	assert.True(t, as110.Hosts[0].Control)
	assert.Equal(t, "host-A", as110.Hosts[0].Name)
}

func TestMixedDefaultAndTaggedGrouping(t *testing.T) {
	parsed := mustTopo(t, `
ASes:
  "1-ff00:0:110": {core: true, voting: true, authoritative: true, issuing: true}
  "1-ff00:0:111": {cert_issuer: 1-ff00:0:110}
  "1-ff00:0:112": {cert_issuer: 1-ff00:0:110}
links:
  - {a: "1-ff00:0:110-A#1", b: "1-ff00:0:111#1", linkAtoB: CHILD}
  - {a: "1-ff00:0:110#2", b: "1-ff00:0:112#1", linkAtoB: CHILD}
`)
	n, err := Hydrate(parsed, NewClabAllocator(parsed, DefaultClabConfig()))
	require.NoError(t, err)
	as110 := findAS(n, "1-ff00:0:110")
	require.Len(t, as110.Hosts, 2)
	// The default (untagged) host is ordered first and carries control+daemon,
	// even though the tagged link appears first in the file.
	assert.Equal(t, "host-1", as110.Hosts[0].Name)
	assert.True(t, as110.Hosts[0].Control)
	assert.Equal(t, "host-A", as110.Hosts[1].Name)
	assert.False(t, as110.Hosts[1].Control)
}

func TestUnderlayFamilies(t *testing.T) {
	n := hydrateTiny(t)
	as112 := findAS(n, "1-ff00:0:112")
	require.NotNil(t, as112)
	// IPv6 AS gets an IPv6 internal subnet.
	assert.True(t, as112.Subnet.Addr().Is6())
	// The 110<->112 link uses IPv6 underlay.
	as110 := findAS(n, "1-ff00:0:110")
	var v6 bool
	for _, br := range as110.BorderRouters {
		for _, intf := range br.Interfaces {
			if intf.RemoteIA == addr.MustParseIA("1-ff00:0:112") {
				v6 = intf.Local.Addr().Is6()
			}
		}
	}
	assert.True(t, v6, "link to 112 should use IPv6 underlay")
}

func TestLinkTypeInversion(t *testing.T) {
	n := hydrateTiny(t)
	// 110 sees 111 as CHILD; 111 sees 110 as PARENT.
	assert.Equal(t, topo.Child, linkTypeBetween(n, "1-ff00:0:110", "1-ff00:0:111"))
	assert.Equal(t, topo.Parent, linkTypeBetween(n, "1-ff00:0:111", "1-ff00:0:110"))
}

func TestDeterminism(t *testing.T) {
	parsed := mustTopo(t, tiny)
	a, err := Hydrate(parsed, NewClabAllocator(parsed, DefaultClabConfig()))
	require.NoError(t, err)
	b, err := Hydrate(parsed, NewClabAllocator(parsed, DefaultClabConfig()))
	require.NoError(t, err)
	ra, err := a.Allocations().Marshal()
	require.NoError(t, err)
	rb, err := b.Allocations().Marshal()
	require.NoError(t, err)
	assert.Equal(t, string(ra), string(rb))
}

func findAS(n *Network, ia string) *AS {
	want := addr.MustParseIA(ia)
	for _, a := range n.ASes {
		if a.IA == want {
			return a
		}
	}
	return nil
}

func linkTypeBetween(n *Network, from, to string) topo.LinkType {
	a := findAS(n, from)
	remote := addr.MustParseIA(to)
	for _, br := range a.BorderRouters {
		for _, intf := range br.Interfaces {
			if intf.RemoteIA == remote {
				return intf.LinkType
			}
		}
	}
	return ""
}
