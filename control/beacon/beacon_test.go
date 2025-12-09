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

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	"github.com/scionproto/scion/pkg/segment"
)

// TestBeaconDiversity tests that diversity is calculated correctly.
func TestBeaconDiversity(t *testing.T) {
	var tests = []struct {
		name   string
		beacon []uint16
		// mBeacon allows to manually specify the other beacon.
		mBeacon   beacon.Beacon
		diversity int
	}{
		{
			name:      "Same beacon",
			beacon:    []uint16{graph.If_130_A_110_X, graph.If_110_X_210_X, graph.If_210_X_220_X},
			diversity: 0,
		},
		{
			name: "Share one link",
			beacon: []uint16{
				graph.If_130_B_120_A, graph.If_120_A_110_X,
				graph.If_110_X_210_X, graph.If_210_X_220_X,
			},
			diversity: 1,
		},
		{
			name: "Distinct",
			beacon: []uint16{
				graph.If_130_B_120_A, graph.If_120_B_220_X,
				graph.If_220_X_210_X, graph.If_210_X_220_X,
			},
			diversity: 2,
		},
		{
			name: "Last link distinct",
			mBeacon: beacon.Beacon{
				Segment: &segment.PathSegment{
					ASEntries: []segment.ASEntry{
						{
							Local: addr.MustParseIA("1-ff00:0:130"),
							Next:  addr.MustParseIA("1-ff00:0:110"),
							HopEntry: segment.HopEntry{
								HopField: segment.HopField{
									ConsEgress: graph.If_130_A_110_X,
								},
							},
						},
						{
							Local: addr.MustParseIA("1-ff00:0:110"),
							Next:  addr.MustParseIA("2-ff00:0:210"),
							HopEntry: segment.HopEntry{
								HopField: segment.HopField{
									ConsIngress: graph.If_110_X_130_A,
									ConsEgress:  2321,
								},
							},
						},
					},
				},
				InIfID: 2123,
			},
			diversity: 1,
		},
	}
	mctrl := gomock.NewController(t)

	g := graph.NewDefaultGraph(mctrl)
	bseg := testBeacon(g, tests[0].beacon...)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			other := test.mBeacon
			if len(test.beacon) > 0 {
				other = testBeacon(g, test.beacon...)
			}
			diversity := bseg.Diversity(other)
			assert.Equal(t, test.diversity, diversity)
		})
	}
}
