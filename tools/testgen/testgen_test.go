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

package testgen_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controlconfig "github.com/scionproto/scion/control/config"
	"github.com/scionproto/scion/private/keyconf"
	"github.com/scionproto/scion/private/topology"
	routerconfig "github.com/scionproto/scion/router/config"
	"github.com/scionproto/scion/tools/testgen"
)

const tinyTopo = `
ASes:
  "1-ff00:0:110": {core: true, voting: true, authoritative: true, issuing: true, mtu: 1400}
  "1-ff00:0:111": {cert_issuer: 1-ff00:0:110}
  "1-ff00:0:112": {cert_issuer: 1-ff00:0:110, underlay: UDP/IPv6}
links:
  - {a: "1-ff00:0:110#1", b: "1-ff00:0:111#41", linkAtoB: CHILD, mtu: 1280}
  - {a: "1-ff00:0:110#2", b: "1-ff00:0:112#1", linkAtoB: CHILD, underlay: UDP/IPv6}
`

func TestPipelineEndToEnd(t *testing.T) {
	dir := t.TempDir()
	topoFile := filepath.Join(dir, "tiny.topo")
	require.NoError(t, os.WriteFile(topoFile, []byte(tinyTopo), 0644))
	gen := filepath.Join(dir, "gen")

	cfg := testgen.DefaultConfig()
	cfg.TopoFile = topoFile
	cfg.OutDir = gen
	require.NoError(t, testgen.Run(cfg))

	// Expected artifacts exist. AS 110's two untagged links share a single
	// border router, so it has exactly one host.
	for _, p := range []string{
		"network-allocations.yml",
		"scion.clab.yml",
		"trcs/ISD1-B1-S1.trc",
		"ASff00_0_110/host-1/config.yml",
		"ASff00_0_110/host-1/topology.json",
		"ASff00_0_110/host-1/network.yaml",
		"ASff00_0_110/host-1/br1-ff00_0_110-1.toml",
		"ASff00_0_110/host-1/cs1-ff00_0_110-1.toml",
		"ASff00_0_110/host-1/disp_cs1-ff00_0_110-1.toml",
		"ASff00_0_110/host-1/sd.toml",
		"ASff00_0_110/crypto/as/cp-as.key",
		"ASff00_0_110/keys/master0.key",
		"ASff00_0_110/keys/master1.key",
	} {
		assert.FileExists(t, filepath.Join(gen, p), p)
	}
	// Master keys load through the real loader.
	mk, err := keyconf.LoadMaster(filepath.Join(gen, "ASff00_0_110/keys"))
	require.NoError(t, err)
	assert.Len(t, mk.Key0, 16)
	assert.Len(t, mk.Key1, 16)
	// The two untagged links collapse onto one host, so there is no host-2.
	assert.NoDirExists(t, filepath.Join(gen, "ASff00_0_110/host-2"))

	// topology.json loads and validates through the real SCION loader.
	for _, p := range []string{
		"ASff00_0_110/host-1/topology.json",
		"ASff00_0_112/host-1/topology.json",
	} {
		_, err := topology.FromJSONFile(filepath.Join(gen, p))
		assert.NoError(t, err, p)
	}

	// Generated TOMLs decode through the real config structs.
	var rc routerconfig.Config
	raw, err := os.ReadFile(filepath.Join(gen, "ASff00_0_110/host-1/br1-ff00_0_110-1.toml"))
	require.NoError(t, err)
	require.NoError(t, toml.Unmarshal(raw, &rc))
	assert.Equal(t, "br1-ff00_0_110-1", rc.General.ID)

	var cc controlconfig.Config
	raw, err = os.ReadFile(filepath.Join(gen, "ASff00_0_110/host-1/cs1-ff00_0_110-1.toml"))
	require.NoError(t, err)
	require.NoError(t, toml.Unmarshal(raw, &cc))
	assert.Equal(t, controlconfig.InProcess, cc.CA.Mode)
}

func TestPipelineDeterministic(t *testing.T) {
	dir := t.TempDir()
	topoFile := filepath.Join(dir, "tiny.topo")
	require.NoError(t, os.WriteFile(topoFile, []byte(tinyTopo), 0644))

	run := func() string {
		gen := filepath.Join(t.TempDir(), "gen")
		cfg := testgen.DefaultConfig()
		cfg.TopoFile = topoFile
		cfg.OutDir = gen
		require.NoError(t, testgen.Run(cfg))
		raw, err := os.ReadFile(filepath.Join(gen, "ASff00_0_110/host-1/config.yml"))
		require.NoError(t, err)
		return string(raw)
	}
	assert.Equal(t, run(), run())
}
