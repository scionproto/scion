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

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beacon/mock_beacon"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	seg "github.com/scionproto/scion/pkg/segment"
)

func TestStoreSegmentsToRegister(t *testing.T) {
	testStoreSelection(t, func(store *beacon.Store) ([]beacon.Beacon, error) {
		return store.SegmentsToRegister(context.Background(), seg.TypeUp)
	})
	testStoreSelection(t, func(store *beacon.Store) ([]beacon.Beacon, error) {
		return store.SegmentsToRegister(context.Background(), seg.TypeDown)
	})
}

func TestStoreBeaconsToPropagate(t *testing.T) {
	testStoreSelection(t, func(store *beacon.Store) ([]beacon.Beacon, error) {
		return store.BeaconsToPropagate(context.Background())
	})
}

func testStoreSelection(t *testing.T,
	methodToTest func(store *beacon.Store) ([]beacon.Beacon, error)) {

	mctrl := gomock.NewController(t)
	defer mctrl.Finish()
	g := graph.NewDefaultGraph(mctrl)

	// Ensure remote out if is set in last AS entry.
	stub := graph.If_111_A_112_X
	beacons := []beacon.Beacon{
		testBeacon(g, graph.If_120_X_111_B, stub),
		testBeacon(g, graph.If_130_B_120_A, graph.If_120_X_111_B, stub),
		testBeacon(g, graph.If_130_B_120_A, graph.If_120_X_111_B, stub),
	}
	stub = graph.If_210_X_220_X
	diverseBeacons := []beacon.Beacon{
		testBeacon(g, graph.If_130_A_110_X, graph.If_110_X_210_X, stub),
		// Same beacon as the first beacon.
		testBeacon(g, graph.If_130_A_110_X, graph.If_110_X_210_X, stub),
		// Share the last link between 110 and 210.
		testBeacon(g, graph.If_130_B_120_A, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
		// Share the last link between 130 and 110.
		testBeacon(g, graph.If_130_A_110_X, graph.If_110_X_120_A, graph.If_120_B_220_X,
			graph.If_220_X_210_X, stub),
		// Share no link.
		testBeacon(g, graph.If_130_B_120_A, graph.If_120_B_220_X, graph.If_220_X_210_X, stub),
		// Share no link.
		testBeacon(g, graph.If_130_B_111_A, graph.If_111_B_120_X, graph.If_120_B_220_X,
			graph.If_220_X_210_X, stub),
	}
	var tests = []struct {
		name     string
		results  []beacon.Beacon
		bestSize int
		expected map[beacon.Beacon]bool
		err      error
	}{
		{
			name:    "Error and no beacons available",
			results: nil,
			err:     errors.New("FAIL"),
		},
		{
			name:     "Available beacons equal best set size",
			results:  beacons,
			bestSize: 3,
			expected: map[beacon.Beacon]bool{
				beacons[0]: true,
				beacons[1]: true,
				beacons[2]: true,
			},
		},
		{
			// This test uses beacons on core links to get more diverse paths.
			// This must not matter to the store anyway.
			name:     "Select shortest most diverse",
			results:  append([]beacon.Beacon{}, diverseBeacons...),
			bestSize: 2,
			expected: map[beacon.Beacon]bool{
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

			db.EXPECT().CandidateBeacons(
				gomock.Any(), gomock.Any(), gomock.Any(), addr.IA(0),
			).Return(
				test.results, test.err,
			)
			res, err := methodToTest(store)
			require.Equal(t, test.err, err)
			seen := make(map[beacon.Beacon]bool)
			for _, b := range res {
				seen[b] = true
			}
			for b := range test.expected {
				if !seen[b] {
					t.Errorf("Expected beacon not seen %s", b)
					return
				}
			}
		})
	}
}

func TestCoreStoreSegmentsToRegister(t *testing.T) {
	testCoreStoreSelection(t, func(store *beacon.CoreStore) ([]beacon.Beacon, error) {
		return store.SegmentsToRegister(context.Background(), seg.TypeCore)
	})
}

func TestCoreStoreBeaconsToPropagate(t *testing.T) {
	testCoreStoreSelection(t, func(store *beacon.CoreStore) ([]beacon.Beacon, error) {
		return store.BeaconsToPropagate(context.Background())
	})
}

func testCoreStoreSelection(t *testing.T,
	methodToTest func(store *beacon.CoreStore) ([]beacon.Beacon, error)) {

	mctrl := gomock.NewController(t)
	defer mctrl.Finish()
	g := graph.NewDefaultGraph(mctrl)

	// Ensure remote out if is set in last AS entry.
	stub := graph.If_210_X_220_X

	ia120 := addr.MustParseIA("1-ff00:0:120")
	beacons120 := []beacon.Beacon{
		testBeacon(g, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
		testBeacon(g, graph.If_120_B_220_X, graph.If_220_X_210_X, stub),
	}
	diverse120 := []beacon.Beacon{
		testBeacon(g, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
		testBeacon(g, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
		testBeacon(g, graph.If_120_B_220_X, graph.If_220_X_210_X, stub),
		testBeacon(g, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
	}

	ia130 := addr.MustParseIA("1-ff00:0:130")
	beacons130 := []beacon.Beacon{
		testBeacon(g, graph.If_130_A_110_X, graph.If_110_X_210_X, stub),
		testBeacon(g, graph.If_130_B_120_A, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
	}
	diverse130 := []beacon.Beacon{
		testBeacon(g, graph.If_130_A_110_X, graph.If_110_X_210_X, stub),
		testBeacon(g, graph.If_130_B_120_A, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
		testBeacon(g, graph.If_130_B_120_A, graph.If_120_B_220_X, graph.If_220_X_210_X, stub),
		testBeacon(g, graph.If_130_B_120_A, graph.If_120_A_110_X, graph.If_110_X_210_X, stub),
	}
	var tests = []struct {
		name     string
		results  map[addr.IA][]beacon.Beacon
		bestSize int
		expected map[beacon.Beacon]bool
	}{
		{
			name: "No beacons available",
		},
		{
			name: "Available beacons equal best set size",
			results: map[addr.IA][]beacon.Beacon{
				ia120: beacons120,
				ia130: beacons130,
			},
			bestSize: 2,
			expected: map[beacon.Beacon]bool{
				beacons120[0]: true,
				beacons120[1]: true,
				beacons130[0]: true,
				beacons130[1]: true,
			},
		},
		{
			name: "Select shortest most diverse",
			results: map[addr.IA][]beacon.Beacon{
				ia120: diverse120,
				ia130: diverse130,
			},
			bestSize: 2,
			expected: map[beacon.Beacon]bool{
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

			db.EXPECT().BeaconSources(gomock.Any()).Return([]addr.IA{ia120, ia130}, nil)
			db.EXPECT().CandidateBeacons(
				gomock.Any(), gomock.Any(), gomock.Any(), ia120,
			).Return(
				test.results[ia120], nil,
			)
			db.EXPECT().CandidateBeacons(
				gomock.Any(), gomock.Any(), gomock.Any(), ia130,
			).Return(
				test.results[ia130], nil,
			)

			res, err := methodToTest(store)
			// CoreStore.getBeacons does not return an error and only logs it.
			require.NoError(t, err)
			seen := make(map[beacon.Beacon]bool)
			for _, b := range res {
				seen[b] = true
			}
			for b := range test.expected {
				if !seen[b] {
					t.Errorf("Expected beacon not seen %s", b)
				}
			}
		})
	}
}

func testBeacon(g *graph.Graph, desc ...uint16) beacon.Beacon {
	pseg := testSegment(g, desc)
	asEntry := pseg.ASEntries[pseg.MaxIdx()]
	return beacon.Beacon{
		InIfID:  asEntry.HopEntry.HopField.ConsIngress,
		Segment: pseg,
	}
}

func testSegment(g *graph.Graph, ifIDs []uint16) *seg.PathSegment {
	pseg := g.Beacon(ifIDs)
	pseg.ASEntries = pseg.ASEntries[:len(pseg.ASEntries)-1]
	return pseg
}
