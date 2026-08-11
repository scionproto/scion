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

package config_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/testing/clab/cmd/controller/config"
)

func sampleConfig() config.Config {
	ap := netip.MustParseAddrPort
	return config.Config{
		SCION: config.SCION{ASes: []config.AS{{
			ISDAS: addr.MustParseIA("1-ff00:0:110"),
			Core:  true,
			MTU:   1400,
			Router: &config.Router{
				ID:                "br1-ff00_0_110-1",
				InternalInterface: ap("10.0.0.1:30042"),
				APIAddr:           ap("10.0.0.1:30442"),
				SCIONMTU:          1400,
			},
			Control: &config.Control{
				ID:      "cs1-ff00_0_110-1",
				Address: ap("10.0.0.1:30252"),
				APIAddr: ap("10.0.0.1:30452"),
				Issuing: true,
			},
			Daemon: &config.Daemon{
				ID:      "sd1-ff00_0_110",
				Address: ap("10.0.0.1:30255"),
				APIAddr: ap("10.0.0.1:30455"),
			},
			Neighbors: []config.Neighbor{{
				ISDAS:        addr.MustParseIA("1-ff00:0:111"),
				Relationship: config.Child,
				Interfaces: []config.Interface{{
					ID:       1,
					Underlay: "UDP/IPv4",
					Address:  ap("10.128.0.1:50000"),
					Remote:   config.Remote{Address: ap("10.128.0.2:50000"), ID: 41},
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

	fromYAML, err := config.DecodeYAML(y)
	require.NoError(t, err)
	fromJSON, err := config.DecodeJSON(j)
	require.NoError(t, err)

	// The structure is normative: YAML and JSON must decode identically.
	assert.Equal(t, fromYAML, fromJSON)
	assert.Equal(t, c, fromYAML)
}
