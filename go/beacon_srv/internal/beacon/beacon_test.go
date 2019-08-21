// Copyright 2019 Anapaya Systems
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

package beacon_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

// TestBeaconDiversity tests that diversity is calculated correctly.
func TestBeaconDiversity(t *testing.T) {
	var tests = []struct {
		name      string
		beacon    []common.IFIDType
		diversity int
	}{
		{
			name: "Same beacon",
			beacon: []common.IFIDType{graph.If_130_A_110_X, graph.If_110_X_210_X,
				graph.If_210_X_220_X},
			diversity: 0,
		},
		{
			name: "Share one link",
			beacon: []common.IFIDType{graph.If_130_B_120_A, graph.If_120_A_110_X,
				graph.If_110_X_210_X, graph.If_210_X_220_X},
			diversity: 1,
		},
		{
			name: "Distinct",
			beacon: []common.IFIDType{graph.If_130_B_120_A, graph.If_120_B_220_X,
				graph.If_220_X_210_X, graph.If_210_X_220_X},
			diversity: 2,
		},
	}
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()
	g := graph.NewDefaultGraph(mctrl)
	bseg := testBeaconOrErr(g, tests[0].beacon...)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			other := testBeaconOrErr(g, test.beacon...)
			diversity := bseg.Beacon.Diversity(other.Beacon)
			assert.Equal(t, test.diversity, diversity)
		})
	}
}
