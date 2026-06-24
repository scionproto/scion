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

package prism

import (
	"net/netip"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controlconfig "github.com/scionproto/scion/control/config"
	daemonconfig "github.com/scionproto/scion/daemon/config"
	"github.com/scionproto/scion/pkg/addr"
	routerconfig "github.com/scionproto/scion/router/config"
)

func sampleConfig() Config {
	ap := netip.MustParseAddrPort
	return Config{
		SCION: SCION{ASes: []AS{{
			ISDAS: addr.MustParseIA("1-ff00:0:110"),
			Core:  true,
			MTU:   1400,
			Router: &Router{
				ID:                "br1-ff00_0_110-1",
				InternalInterface: ap("10.0.0.1:30042"),
				APIAddr:           ap("10.0.0.1:30442"),
				SCIONMTU:          1400,
			},
			Control: &Control{
				ID:      "cs1-ff00_0_110-1",
				Address: ap("10.0.0.1:30252"),
				APIAddr: ap("10.0.0.1:30452"),
				Issuing: true,
			},
			Daemon: &Daemon{
				ID:      "sd1-ff00_0_110",
				Address: ap("10.0.0.1:30255"),
				APIAddr: ap("10.0.0.1:30455"),
			},
			Neighbors: []Neighbor{{
				ISDAS:        addr.MustParseIA("1-ff00:0:111"),
				Relationship: Child,
				Interfaces: []Interface{{
					ID:       1,
					Underlay: "UDP/IPv4",
					Address:  ap("10.128.0.1:50000"),
					Remote:   Remote{Address: ap("10.128.0.2:50000"), ID: 41},
					MTU:      1280,
				}},
			}},
		}}},
	}
}

func TestEncodeDecodeEquivalent(t *testing.T) {
	c := sampleConfig()

	y, err := c.EncodeYAML()
	require.NoError(t, err)
	j, err := c.EncodeJSON()
	require.NoError(t, err)

	fromYAML, err := DecodeYAML(y)
	require.NoError(t, err)
	fromJSON, err := DecodeJSON(j)
	require.NoError(t, err)

	// The structure is normative: YAML and JSON must decode identically.
	assert.Equal(t, fromYAML, fromJSON)
	assert.Equal(t, c, fromYAML)
}

func TestRenderDecodesThroughRealConfigs(t *testing.T) {
	files, err := Render(sampleConfig())
	require.NoError(t, err)

	byName := map[string][]byte{}
	for _, f := range files {
		byName[f.Name] = f.Content
	}
	require.Contains(t, byName, "br1-ff00_0_110-1.toml")
	require.Contains(t, byName, "cs1-ff00_0_110-1.toml")
	require.Contains(t, byName, "sd1-ff00_0_110.toml")

	var rc routerconfig.Config
	require.NoError(t, toml.Unmarshal(byName["br1-ff00_0_110-1.toml"], &rc))
	assert.Equal(t, "br1-ff00_0_110-1", rc.General.ID)
	assert.Equal(t, "10.0.0.1:30442", rc.API.Addr)

	var cc controlconfig.Config
	require.NoError(t, toml.Unmarshal(byName["cs1-ff00_0_110-1.toml"], &cc))
	assert.Equal(t, "cs1-ff00_0_110-1", cc.General.ID)
	assert.Equal(t, controlconfig.InProcess, cc.CA.Mode)

	var dc daemonconfig.Config
	require.NoError(t, toml.Unmarshal(byName["sd1-ff00_0_110.toml"], &dc))
	assert.Equal(t, "sd1-ff00_0_110", dc.General.ID)
	assert.Equal(t, "10.0.0.1:30255", dc.SD.Address)
}

func TestRenderOnlyPresentElements(t *testing.T) {
	// A border-router-only host yields exactly one file.
	c := Config{SCION: SCION{ASes: []AS{{
		ISDAS:  addr.MustParseIA("1-ff00:0:110"),
		Router: &Router{ID: "br1-ff00_0_110-2", InternalInterface: netip.MustParseAddrPort("10.0.0.2:30042")},
	}}}}
	files, err := Render(c)
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, "br1-ff00_0_110-2.toml", files[0].Name)
}
