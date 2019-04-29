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
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/beacon_srv/internal/beacon/mock_beacon"
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

	// Ensure remote out if is set in last AS entry.
	e := graph.If_111_A_112_X
	beacons := [][]common.IFIDType{
		{graph.If_120_X_111_B, e},
		{graph.If_130_B_120_A, graph.If_120_X_111_B, e},
		{graph.If_130_B_120_A, graph.If_120_X_111_B, e},
	}
	e = graph.If_210_X_220_X
	// Beacons with high diversity.
	diversePaths := [][]common.IFIDType{
		{graph.If_130_A_110_X, graph.If_110_X_210_X, e},
		// Same beacon as the first beacon.
		{graph.If_130_A_110_X, graph.If_110_X_210_X, e},
		// Share the last link between 110 and 210.
		{graph.If_130_B_120_A, graph.If_120_A_110_X, graph.If_110_X_210_X, e},
		// Share the last link between 130 and 110.
		{graph.If_130_A_110_X, graph.If_110_X_120_A, graph.If_120_B_220_X, graph.If_220_X_210_X, e},
		// Share no link.
		{graph.If_130_B_120_A, graph.If_120_B_220_X, graph.If_220_X_210_X, e},
		// Share no link.
		{graph.If_130_B_111_A, graph.If_111_B_120_X, graph.If_120_B_220_X, graph.If_220_X_210_X, e},
	}

	var tests = []struct {
		name      string
		beacons   [][]common.IFIDType
		err       error
		bestSize  int
		expected  map[int]bool
		expectErr bool
	}{
		{
			name:      "Error on first beacon",
			beacons:   [][]common.IFIDType{},
			err:       errors.New("Fail"),
			bestSize:  5,
			expectErr: true,
		},
		{
			name:      "Error after first beacon",
			beacons:   beacons[:1],
			err:       errors.New("Fail"),
			bestSize:  5,
			expected:  map[int]bool{0: true},
			expectErr: true,
		},
		{
			name:      "Error on last beacon of set size",
			beacons:   beacons[:2],
			err:       errors.New("Fail"),
			bestSize:  3,
			expected:  map[int]bool{0: true, 1: true},
			expectErr: true,
		},
		{
			name:     "Available beacons equal best set size",
			beacons:  beacons,
			bestSize: 3,
			expected: map[int]bool{0: true, 1: true, 2: true},
		},
		{
			name:     "Error after last beacon of set size",
			beacons:  beacons,
			err:      errors.New("Fail"),
			bestSize: 3,
			expected: map[int]bool{0: true, 1: true, 2: true},
		},
		{
			// This test uses beacons on core links to get more diverse paths.
			// This must not matter to the store anyway.
			name:     "Select shortest most diverse",
			beacons:  diversePaths,
			err:      errors.New("Fail"),
			bestSize: 2,
			expected: map[int]bool{0: true, 4: true},
		},
	}
	for _, test := range tests {
		Convey(test.name, t, func() {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			g := graph.NewDefaultGraph(mctrl)
			db := mock_beacon.NewMockDB(mctrl)
			prop := beacon.Policy{BestSetSize: test.bestSize, Type: beacon.PropPolicy}
			up := beacon.Policy{BestSetSize: test.bestSize, Type: beacon.UpRegPolicy}
			down := beacon.Policy{BestSetSize: test.bestSize, Type: beacon.DownRegPolicy}
			store := beacon.NewBeaconStore(prop, up, down, db)

			expected := make(map[*seg.PathSegment]bool)
			db.EXPECT().CandidateBeacons(gomock.Any(), gomock.Any(), gomock.Any(),
				addr.IA{}).DoAndReturn(
				func(_ ...interface{}) (<-chan beacon.BeaconOrErr, error) {
					res := make(chan beacon.BeaconOrErr, testLen(len(test.beacons),
						test.err != nil))
					defer close(res)
					for i, testBeacon := range test.beacons {
						bseg := testBeaconOrErr(g, testBeacon)
						if test.expected[i] {
							expected[bseg.Beacon.Segment] = true
						}
						res <- bseg
					}
					if test.err != nil {
						res <- beacon.BeaconOrErr{Err: test.err}
					}
					return res, nil
				},
			)

			res, err := methodToTest(store)
			SoMsg("Err", err, ShouldBeNil)
			var all []beacon.BeaconOrErr
			for bOrErr := range res {
				all = append(all, bOrErr)
			}
			SoMsg("Len", len(all), ShouldEqual, testLen(len(test.expected), test.expectErr))
			for _, bOrErr := range all {
				if bOrErr.Err == nil {
					SoMsg(fmt.Sprintf("Expect %s", bOrErr.Beacon), expected[bOrErr.Beacon.Segment],
						ShouldBeTrue)
				} else {
					xtest.SoMsgError("Err expected", bOrErr.Err, test.expectErr)
				}
			}
		})
	}
}

func testLen(beaconLen int, err bool) int {
	if err {
		return beaconLen + 1
	}
	return beaconLen
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
	// Ensure remote out if is set in last AS entry.
	e := graph.If_210_X_220_X
	ia120 := xtest.MustParseIA("1-ff00:0:120")
	beacons120 := [][]common.IFIDType{
		{graph.If_120_A_110_X, graph.If_110_X_210_X, e},
		{graph.If_120_B_220_X, graph.If_220_X_210_X, e},
	}
	ia130 := xtest.MustParseIA("1-ff00:0:130")
	beacons130 := [][]common.IFIDType{
		{graph.If_130_A_110_X, graph.If_110_X_210_X, e},
		{graph.If_130_B_120_A, graph.If_120_A_110_X, graph.If_110_X_210_X, e},
	}
	type rep struct {
		beacons [][]common.IFIDType
		err     error
	}
	var tests = []struct {
		name      string
		reps      map[addr.IA]rep
		bestSize  int
		expected  map[addr.IA]map[int]bool
		expectErr bool
	}{
		{
			name: "Error on first beacon",
			reps: map[addr.IA]rep{
				ia120: {err: errors.New("Fail")},
				ia130: {beacons: beacons130},
			},
			bestSize:  2,
			expected:  map[addr.IA]map[int]bool{ia130: {0: true, 1: true}},
			expectErr: true,
		},
		{
			name: "Error after first beacon",
			reps: map[addr.IA]rep{
				ia120: {beacons: beacons120[:1], err: errors.New("Fail")},
				ia130: {beacons: beacons130},
			},
			bestSize:  2,
			expected:  map[addr.IA]map[int]bool{ia120: {0: true}, ia130: {0: true, 1: true}},
			expectErr: true,
		},
		{
			name: "Available beacons equal best set size",
			reps: map[addr.IA]rep{
				ia120: {beacons: beacons120},
				ia130: {beacons: beacons130},
			},
			bestSize: 2,
			expected: map[addr.IA]map[int]bool{
				ia120: {0: true, 1: true},
				ia130: {0: true, 1: true},
			},
		},
		{
			name: "Error after last beacon of set size",
			reps: map[addr.IA]rep{
				ia120: {beacons: beacons120, err: errors.New("Fail")},
				ia130: {beacons: beacons130},
			},
			bestSize: 2,
			expected: map[addr.IA]map[int]bool{
				ia120: {0: true, 1: true},
				ia130: {0: true, 1: true},
			},
		},
		{
			name: "Select shortest most diverse",
			reps: map[addr.IA]rep{
				ia120: {beacons: [][]common.IFIDType{
					{graph.If_120_A_110_X, graph.If_110_X_210_X, e},
					{graph.If_120_A_110_X, graph.If_110_X_210_X, e},
					{graph.If_120_B_220_X, graph.If_220_X_210_X, e},
					{graph.If_120_A_110_X, graph.If_110_X_210_X, e},
				}},
				ia130: {beacons: [][]common.IFIDType{
					{graph.If_130_A_110_X, graph.If_110_X_210_X, e},
					{graph.If_130_B_120_A, graph.If_120_A_110_X, graph.If_110_X_210_X, e},
					{graph.If_130_B_120_A, graph.If_120_B_220_X, graph.If_220_X_210_X, e},
					{graph.If_130_B_120_A, graph.If_120_A_110_X, graph.If_110_X_210_X, e},
				}},
			},
			bestSize: 2,
			expected: map[addr.IA]map[int]bool{
				ia120: {0: true, 2: true},
				ia130: {0: true, 2: true},
			},
		},
	}
	for _, test := range tests {
		Convey(test.name, t, func() {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			g := graph.NewDefaultGraph(mctrl)
			db := mock_beacon.NewMockDB(mctrl)
			tx := mock_beacon.NewMockTransaction(mctrl)
			prop := beacon.Policy{BestSetSize: test.bestSize, Type: beacon.PropPolicy}
			reg := beacon.Policy{BestSetSize: test.bestSize, Type: beacon.CoreRegPolicy}
			store := beacon.NewCoreBeaconStore(prop, reg, db)

			expected := make(map[*seg.PathSegment]bool)
			// respFunc serves beacons on the returned channel.
			type respFunc func(_ ...interface{}) (<-chan beacon.BeaconOrErr, error)
			// responder is a factory that generates a function serving the specified beacons.
			responder := func(ia addr.IA) respFunc {
				return func(_ ...interface{}) (<-chan beacon.BeaconOrErr, error) {
					res := make(chan beacon.BeaconOrErr, testLen(len(test.reps[ia].beacons),
						test.reps[ia].err != nil))
					defer close(res)
					for i, testBeacon := range test.reps[ia].beacons {
						bseg := testBeaconOrErr(g, testBeacon)
						if test.expected[ia][i] {
							expected[bseg.Beacon.Segment] = true
						}
						res <- bseg
					}
					if test.reps[ia].err != nil {
						res <- beacon.BeaconOrErr{Err: test.reps[ia].err}
					}
					return res, nil
				}
			}
			db.EXPECT().BeginTransaction(gomock.Any(), gomock.Any()).Return(tx, nil)
			tx.EXPECT().Commit()
			tx.EXPECT().BeaconSources(gomock.Any()).Return([]addr.IA{ia120, ia130}, nil)
			tx.EXPECT().CandidateBeacons(gomock.Any(), gomock.Any(), gomock.Any(),
				ia120).DoAndReturn(responder(ia120))
			tx.EXPECT().CandidateBeacons(gomock.Any(), gomock.Any(), gomock.Any(),
				ia130).DoAndReturn(responder(ia130))

			res, err := methodToTest(store)
			SoMsg("Err", err, ShouldBeNil)
			var all []beacon.BeaconOrErr
			for bOrErr := range res {
				all = append(all, bOrErr)
			}
			expBeaconCount := len(test.expected[ia120]) + len(test.expected[ia130])
			SoMsg("Len", len(all), ShouldEqual, testLen(expBeaconCount, test.expectErr))
			for _, bOrErr := range all {
				if bOrErr.Err == nil {
					SoMsg(fmt.Sprintf("Expect %s", bOrErr.Beacon), expected[bOrErr.Beacon.Segment],
						ShouldBeTrue)
				} else {
					xtest.SoMsgError("Err expected", bOrErr.Err, test.expectErr)
				}
			}
		})
	}
}

func testBeaconOrErr(g *graph.Graph, desc []common.IFIDType) beacon.BeaconOrErr {
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
