// Copyright 2020 ETH Zurich
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

package combinator

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

func TestMetadataLatency(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	g := graph.NewDefaultGraph(ctrl)

	testCases := []struct {
		Name      string
		Path      []snet.PathInterface
		ASEntries []seg.ASEntry
	}{{
		Name: "#0 simple up-core-down",
		Path: []snet.PathInterface{
			{IA: xtest.MustParseIA("1-ff00:0:131"), ID: graph.If_131_X_130_A},
			{IA: xtest.MustParseIA("1-ff00:0:130"), ID: graph.If_130_A_131_X},
			{IA: xtest.MustParseIA("1-ff00:0:130"), ID: graph.If_130_B_120_A},
			{IA: xtest.MustParseIA("1-ff00:0:120"), ID: graph.If_120_A_130_B},
			{IA: xtest.MustParseIA("1-ff00:0:120"), ID: graph.If_120_X_111_B},
			{IA: xtest.MustParseIA("1-ff00:0:111"), ID: graph.If_111_B_120_X},
		},
		ASEntries: concatASEntries(
			g.BeaconWithStaticInfo([]common.IFIDType{graph.If_130_A_131_X}).ASEntries,
			g.BeaconWithStaticInfo([]common.IFIDType{graph.If_120_A_130_B}).ASEntries,
			g.BeaconWithStaticInfo([]common.IFIDType{graph.If_120_X_111_B}).ASEntries,
		),
	}}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			metadata := collectMetadata(tc.Path, tc.ASEntries)
			checkLatency(t, g, tc.Path, metadata.Latency)
		})
	}
}

func checkLatency(t *testing.T, g *graph.Graph,
	path []snet.PathInterface, latency []time.Duration) {

	if len(path) == 0 {
		assert.Equal(t, len(latency), 0)
		return
	}

	assert.Equal(t, len(latency), len(path)-1)
	for i := 0; i < len(path)-1; i++ {
		ifid_a := path[i].ID
		ifid_b := path[i+1].ID
		assert.Equal(t, g.Latency(ifid_a, ifid_b), latency[i])
	}
}

func concatASEntries(up, core, down []seg.ASEntry) []seg.ASEntry {
	reverseASEntries(up)
	reverseASEntries(core)
	r := append(up, core...)
	r = append(r, down...)
	return r
}
