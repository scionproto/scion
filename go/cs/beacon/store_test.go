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
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beacon/mock_beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/proto"
)

func TestStoreSegmentsToRegister(t *testing.T) {
	testStoreSelection(t, func(store *beacon.Store) (<-chan beacon.BeaconOrErr, error) {
		return store.SegmentsToRegister(context.Background(), proto.PathSegType_up)
	})
	testStoreSelection(t, func(store *beacon.Store) (<-chan beacon.BeaconOrErr, error) {
		return store.SegmentsToRegister(context.Background(), proto.PathSegType_down)
	})
}

func TestStoreBeaconsToPropagate(t *testing.T) {
	testStoreSelection(t, func(store *beacon.Store) (<-chan beacon.BeaconOrErr, error) {
		return store.BeaconsToPropagate(context.Background())
	})
}

func testStoreSelection(t *testing.T,
	methodToTest func(store *beacon.Store) (<-chan beacon.BeaconOrErr, error)) {
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()
	g := graph.NewDefaultGraph(mctrl)

	// Ensure remote out if is set in last AS entry.
	stub := graph.If_111_A_112_X
	beacons := []beacon.BeaconOrErr{
		testBeaconOrErr(g, graph.If_120_X_111_B, stub),
		testBeaconOrErr(g, graph.If_130_B_120_A, graph.If_120_X_111_B, stub),
		testBeaconOrErr(g, graph.If_130_B_120_A, graph.If_120_X_111_B, stub),
	}
	stub = graph.If_210_X_220_X
	diverseBeacons := []beacon.BeaconOrErr{
		testBeaconOrErr(g, graph.If_130_A_110_X, graph.If_110_X_210_X, stub),
		// Same beacon as the first beacon.
		testBeaconOrErr(g, graph.If_130_A_110_X, graph.If_110_X_210_X, stub),
		// Share the last link between 110 and 210.
		testBeaconOrErr(g, graph.If_130_B_120_A, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
		// Share the last link between 130 and 110.
		testBeaconOrErr(g, graph.If_130_A_110_X, graph.If_110_X_120_A, graph.If_120_B_220_X,
			graph.If_220_X_210_X, stub),
		// Share no link.
		testBeaconOrErr(g, graph.If_130_B_120_A, graph.If_120_B_220_X, graph.If_220_X_210_X, stub),
		// Share no link.
		testBeaconOrErr(g, graph.If_130_B_111_A, graph.If_111_B_120_X, graph.If_120_B_220_X,
			graph.If_220_X_210_X, stub),
	}
	beaconErr := beacon.BeaconOrErr{Err: errors.New("Fail")}
	var tests = []struct {
		name      string
		results   []beacon.BeaconOrErr
		bestSize  int
		expected  map[beacon.BeaconOrErr]bool
		expectErr bool
	}{
		{
			name:      "Error on first beacon",
			results:   []beacon.BeaconOrErr{beaconErr},
			bestSize:  5,
			expectErr: true,
		},
		{
			name:      "Error after first beacon",
			results:   []beacon.BeaconOrErr{beacons[0], beaconErr},
			bestSize:  5,
			expected:  map[beacon.BeaconOrErr]bool{beacons[0]: true},
			expectErr: true,
		},
		{
			name:     "Error on last beacon of set size",
			results:  append(append([]beacon.BeaconOrErr{}, beacons[:2]...), beaconErr),
			bestSize: 3,
			expected: map[beacon.BeaconOrErr]bool{
				beacons[0]: true,
				beacons[1]: true,
			},
			expectErr: true,
		},
		{
			name:     "Available beacons equal best set size",
			results:  beacons,
			bestSize: 3,
			expected: map[beacon.BeaconOrErr]bool{
				beacons[0]: true,
				beacons[1]: true,
				beacons[2]: true,
			},
		},
		{
			name:     "Error after last beacon of set size",
			results:  append(append([]beacon.BeaconOrErr{}, beacons...), beaconErr),
			bestSize: 3,
			expected: map[beacon.BeaconOrErr]bool{
				beacons[0]: true,
				beacons[1]: true,
				beacons[2]: true,
			},
		},
		{
			name:     "Error in the middle of beacons",
			results:  append(append([]beacon.BeaconOrErr{}, beacons[0], beaconErr), beacons[1:]...),
			bestSize: 3,
			expected: map[beacon.BeaconOrErr]bool{
				beacons[0]: true,
				beacons[1]: true,
				beacons[2]: true,
			},
			expectErr: true,
		},
		{
			// This test uses beacons on core links to get more diverse paths.
			// This must not matter to the store anyway.
			name:     "Select shortest most diverse",
			results:  append(append([]beacon.BeaconOrErr{}, diverseBeacons...), beaconErr),
			bestSize: 2,
			expected: map[beacon.BeaconOrErr]bool{
				diverseBeacons[0]: true,
				diverseBeacons[4]: true,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			db := mock_beacon.NewMockDB(mctrl)
			policies := beacon.Policies{
				Prop:    beacon.Policy{BestSetSize: test.bestSize},
				UpReg:   beacon.Policy{BestSetSize: test.bestSize},
				DownReg: beacon.Policy{BestSetSize: test.bestSize},
			}
			store, err := beacon.NewBeaconStore(policies, db)
			require.NoError(t, err)
			db.EXPECT().CandidateBeacons(gomock.Any(), gomock.Any(), gomock.Any(),
				addr.IA{}).DoAndReturn(
				func(_ ...interface{}) (<-chan beacon.BeaconOrErr, error) {
					results := make(chan beacon.BeaconOrErr, len(test.results))
					defer close(results)
					for _, res := range test.results {
						results <- res
					}
					return results, nil
				},
			)
			res, err := methodToTest(store)
			xtest.FailOnErr(t, err, "err")
			seen := make(map[beacon.BeaconOrErr]bool)
			for bOrErr := range res {
				if bOrErr.Err == nil {
					if !test.expected[bOrErr] {
						t.Errorf("Unexpected beacon %s", bOrErr.Beacon)
					}
					seen[bOrErr] = true
				} else if !test.expectErr {
					t.Errorf("Error not expected %s", bOrErr.Err)
				}
			}
			for bOrErr := range test.expected {
				if !seen[bOrErr] {
					t.Errorf("Expected beacon not seen %s", bOrErr.Beacon)
				}
			}
		})
	}
}

func TestCoreStoreSegmentsToRegister(t *testing.T) {
	testCoreStoreSelection(t, func(store *beacon.CoreStore) (<-chan beacon.BeaconOrErr, error) {
		return store.SegmentsToRegister(context.Background(), proto.PathSegType_core)
	})
}

func TestCoreStoreBeaconsToPropagate(t *testing.T) {
	testCoreStoreSelection(t, func(store *beacon.CoreStore) (<-chan beacon.BeaconOrErr, error) {
		return store.BeaconsToPropagate(context.Background())
	})
}

func testCoreStoreSelection(t *testing.T,
	methodToTest func(store *beacon.CoreStore) (<-chan beacon.BeaconOrErr, error)) {
	mctrl := gomock.NewController(t)
	defer mctrl.Finish()
	g := graph.NewDefaultGraph(mctrl)

	beaconErr := beacon.BeaconOrErr{Err: errors.New("Fail")}
	// Ensure remote out if is set in last AS entry.
	stub := graph.If_210_X_220_X

	ia120 := xtest.MustParseIA("1-ff00:0:120")
	beacons120 := []beacon.BeaconOrErr{
		testBeaconOrErr(g, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
		testBeaconOrErr(g, graph.If_120_B_220_X, graph.If_220_X_210_X, stub),
	}
	diverse120 := []beacon.BeaconOrErr{
		testBeaconOrErr(g, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
		testBeaconOrErr(g, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
		testBeaconOrErr(g, graph.If_120_B_220_X, graph.If_220_X_210_X, stub),
		testBeaconOrErr(g, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
	}

	ia130 := xtest.MustParseIA("1-ff00:0:130")
	beacons130 := []beacon.BeaconOrErr{
		testBeaconOrErr(g, graph.If_130_A_110_X, graph.If_110_X_210_X, stub),
		testBeaconOrErr(g, graph.If_130_B_120_A, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
	}
	diverse130 := []beacon.BeaconOrErr{
		testBeaconOrErr(g, graph.If_130_A_110_X, graph.If_110_X_210_X, stub),
		testBeaconOrErr(g, graph.If_130_B_120_A, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
		testBeaconOrErr(g, graph.If_130_B_120_A, graph.If_120_B_220_X, graph.If_220_X_210_X, stub),
		testBeaconOrErr(g, graph.If_130_B_120_A, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
	}
	var tests = []struct {
		name      string
		results   map[addr.IA][]beacon.BeaconOrErr
		bestSize  int
		expected  map[beacon.BeaconOrErr]bool
		expectErr bool
	}{
		{
			name: "Error on first beacon",
			results: map[addr.IA][]beacon.BeaconOrErr{
				ia120: {beaconErr},
				ia130: beacons130,
			},
			bestSize: 2,
			expected: map[beacon.BeaconOrErr]bool{
				beacons130[0]: true,
				beacons130[1]: true,
			},
			expectErr: true,
		},
		{
			name: "Error after first beacon",
			results: map[addr.IA][]beacon.BeaconOrErr{
				ia120: {beacons120[0], beaconErr},
				ia130: beacons130,
			},
			bestSize: 2,
			expected: map[beacon.BeaconOrErr]bool{
				beacons120[0]: true,
				beacons130[0]: true,
				beacons130[1]: true,
			},
			expectErr: true,
		},
		{
			name: "Available beacons equal best set size",
			results: map[addr.IA][]beacon.BeaconOrErr{
				ia120: beacons120,
				ia130: beacons130,
			},
			bestSize: 2,
			expected: map[beacon.BeaconOrErr]bool{
				beacons120[0]: true,
				beacons120[1]: true,
				beacons130[0]: true,
				beacons130[1]: true,
			},
		},
		{
			name: "Error after last beacon of set size",
			results: map[addr.IA][]beacon.BeaconOrErr{
				ia120: append(append([]beacon.BeaconOrErr{}, beacons120...), beaconErr),
				ia130: beacons130,
			},
			bestSize: 2,
			expected: map[beacon.BeaconOrErr]bool{
				beacons120[0]: true,
				beacons120[1]: true,
				beacons130[0]: true,
				beacons130[1]: true,
			},
		},
		{
			name: "Select shortest most diverse",
			results: map[addr.IA][]beacon.BeaconOrErr{
				ia120: diverse120,
				ia130: diverse130,
			},
			bestSize: 2,
			expected: map[beacon.BeaconOrErr]bool{
				diverse120[0]: true,
				diverse120[2]: true,
				diverse130[0]: true,
				diverse130[2]: true,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			db := mock_beacon.NewMockDB(mctrl)
			policies := beacon.CorePolicies{
				Prop:    beacon.Policy{BestSetSize: test.bestSize},
				CoreReg: beacon.Policy{BestSetSize: test.bestSize},
			}
			store, err := beacon.NewCoreBeaconStore(policies, db)
			require.NoError(t, err)
			// respFunc serves beacons on the returned channel.
			type respFunc func(_ ...interface{}) (<-chan beacon.BeaconOrErr, error)
			// responder is a factory that generates a function serving the specified beacons.
			responder := func(ia addr.IA) respFunc {
				return func(_ ...interface{}) (<-chan beacon.BeaconOrErr, error) {
					results := make(chan beacon.BeaconOrErr, len(test.results[ia]))
					defer close(results)
					for _, res := range test.results[ia] {
						results <- res
					}
					return results, nil
				}
			}
			db.EXPECT().BeaconSources(gomock.Any()).Return([]addr.IA{ia120, ia130}, nil)
			db.EXPECT().CandidateBeacons(gomock.Any(), gomock.Any(), gomock.Any(),
				ia120).DoAndReturn(responder(ia120))
			db.EXPECT().CandidateBeacons(gomock.Any(), gomock.Any(), gomock.Any(),
				ia130).DoAndReturn(responder(ia130))

			res, err := methodToTest(store)
			xtest.FailOnErr(t, err, "err")
			seen := make(map[beacon.BeaconOrErr]bool)
			for bOrErr := range res {
				if bOrErr.Err == nil {
					if !test.expected[bOrErr] {
						t.Errorf("Unexpected beacon %s", bOrErr.Beacon)
					}
					seen[bOrErr] = true
				} else if !test.expectErr {
					t.Errorf("Error not expected %s", bOrErr.Err)
				}
			}
			for bOrErr := range test.expected {
				if !seen[bOrErr] {
					t.Errorf("Expected beacon not seen %s", bOrErr.Beacon)
				}
			}
		})
	}
}

func testBeaconOrErr(g *graph.Graph, desc ...common.IFIDType) beacon.BeaconOrErr {
	pseg := testBeacon(g, desc)
	asEntry := pseg.ASEntries[pseg.MaxAEIdx()]
	return beacon.BeaconOrErr{
		Beacon: beacon.Beacon{
			InIfId:  asEntry.HopEntries[0].RemoteOutIF,
			Segment: pseg,
		},
	}
}

func testBeacon(g *graph.Graph, ifids []common.IFIDType) *seg.PathSegment {
	pseg := g.Beacon(ifids)
	pseg.RawASEntries = pseg.RawASEntries[:len(pseg.RawASEntries)-1]
	pseg.ASEntries = pseg.ASEntries[:len(pseg.ASEntries)-1]
	return pseg
}
