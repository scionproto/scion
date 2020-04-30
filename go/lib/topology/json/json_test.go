// Copyright 2019 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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

package json_test

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	jsontopo "github.com/scionproto/scion/go/lib/topology/json"
)

var (
	update = flag.Bool("update", false, "set to true to update golden files")
)

func TestLoadRawFromFile(t *testing.T) {
	referenceTopology := &jsontopo.Topology{
		Timestamp:      168562800,
		TimestampHuman: "May  6 00:00:00 CET 1975",
		IA:             "6-ff00:0:362",
		MTU:            1472,
		Attributes:     []trc.Attribute{trc.Authoritative, trc.Core, trc.Issuing, trc.Voting},
		BorderRouters: map[string]*jsontopo.BRInfo{
			"borderrouter6-f00:0:362-1": {
				InternalAddr: "10.1.0.1:0",
				CtrlAddr:     "10.1.0.1:30098",
				Interfaces: map[common.IFIDType]*jsontopo.BRInterface{
					91: {
						Underlay: jsontopo.Underlay{
							Public: "192.0.2.1:4997",
							Remote: "192.0.2.2:4998",
							Bind:   "10.0.0.1",
						},
						Bandwidth: 100000,
						IA:        "6-ff00:0:363",
						LinkTo:    "CORE",
						MTU:       1472,
					},
				},
			},
			"borderrouter6-f00:0:362-9": {
				InternalAddr: "[2001:db8:a0b:12f0::2]:0",
				CtrlAddr:     "[2001:db8:a0b:12f0::2300]:30098",
				Interfaces: map[common.IFIDType]*jsontopo.BRInterface{
					32: {
						Underlay: jsontopo.Underlay{
							Public: "[2001:db8:a0b:12f0::1]:4997",
							Remote: "[2001:db8:a0b:12f0::2]:4998",
							Bind:   "2001:db8:a0b:12f0::8",
						},
						Bandwidth: 5000,
						IA:        "6-ff00:0:364",
						LinkTo:    "CHILD",
						MTU:       4430,
					},
				},
			},
		},
	}

	if *update {
		b, err := json.MarshalIndent(referenceTopology, "", "  ")
		require.NoError(t, err)
		b = append(b, []byte("\n")...)
		err = ioutil.WriteFile("testdata/topology.json", b, 0644)
		require.NoError(t, err)
	}

	t.Run("unmarshaled struct matches", func(t *testing.T) {
		loadedTopology, err := jsontopo.LoadFromFile("testdata/topology.json")
		assert.NoError(t, err)
		assert.Equal(t, referenceTopology, loadedTopology)
	})
	t.Run("marshaled bytes match", func(t *testing.T) {
		referenceTopologyBytes, err := ioutil.ReadFile("testdata/topology.json")
		require.NoError(t, err)
		topologyBytes, err := json.MarshalIndent(referenceTopology, "", "  ")
		require.NoError(t, err)
		assert.Equal(t,
			strings.TrimSpace(string(referenceTopologyBytes)),
			strings.TrimSpace(string(topologyBytes)),
		)
	})
}
