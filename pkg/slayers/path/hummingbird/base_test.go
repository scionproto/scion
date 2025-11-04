// Copyright 2025 ETH Zurich
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

package hummingbird_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
)

func TestIncPath(t *testing.T) {
	testCases := map[string]struct {
		nsegs, nhops     int
		segLens          [3]uint8
		inIdxs, wantIdxs [][2]int
	}{
		"1 segment, 2 hops": {
			nsegs:    1,
			nhops:    6,
			segLens:  [3]uint8{6, 0, 0},
			inIdxs:   [][2]int{{0, 0}, {0, 3}},
			wantIdxs: [][2]int{{0, 3}, {0, 0}},
		},
		"1 segment, 5 hops": {
			nsegs:    1,
			nhops:    15,
			segLens:  [3]uint8{15, 0, 0},
			inIdxs:   [][2]int{{0, 0}, {0, 3}, {0, 6}, {0, 9}, {0, 12}},
			wantIdxs: [][2]int{{0, 3}, {0, 6}, {0, 9}, {0, 12}, {0, 0}},
		},
		"2 segments, 5 hops": {
			nsegs:    2,
			nhops:    15,
			segLens:  [3]uint8{6, 9, 0},
			inIdxs:   [][2]int{{0, 0}, {0, 3}, {1, 6}, {1, 9}, {1, 12}},
			wantIdxs: [][2]int{{0, 3}, {1, 6}, {1, 9}, {1, 12}, {0, 0}},
		},
		"3 segments, 9 hops": {
			nsegs:   3,
			nhops:   27,
			segLens: [3]uint8{6, 12, 9},
			inIdxs: [][2]int{
				{0, 0}, {0, 3}, {1, 6}, {1, 9}, {1, 12}, {1, 15}, {2, 18}, {2, 21}, {2, 24},
			},
			wantIdxs: [][2]int{
				{0, 3}, {1, 6}, {1, 9}, {1, 12}, {1, 15}, {2, 18}, {2, 21}, {2, 24}, {0, 0},
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		for i := range tc.inIdxs {
			i := i
			t.Run(fmt.Sprintf("%s case %d", name, i+1), func(t *testing.T) {
				t.Parallel()
				s := hummingbird.Base{
					PathMeta: hummingbird.MetaHdr{
						CurrINF: uint8(tc.inIdxs[i][0]),
						CurrHF:  uint8(tc.inIdxs[i][1]),
						SegLen:  tc.segLens,
					},
					NumINF:   tc.nsegs,
					NumLines: tc.nhops,
				}
				err := s.IncPath(3)
				if tc.wantIdxs[i][0] == 0 && tc.wantIdxs[i][1] == 0 {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, uint8(tc.wantIdxs[i][0]), s.PathMeta.CurrINF, "CurrINF")
					assert.Equal(t, uint8(tc.wantIdxs[i][1]), s.PathMeta.CurrHF, "CurrHF")
				}

			})
		}
	}
}

func TestBaseIsXOver(t *testing.T) {
	testCases := map[string]struct {
		nsegs, nhops int
		segLens      [3]uint8
		inIdxs       [][2]int
		xover        []bool
	}{
		"1 segment, 2 hops": {
			nsegs:   1,
			nhops:   6,
			segLens: [3]uint8{6, 0, 0},
			inIdxs:  [][2]int{{0, 0}, {0, 3}},
			xover:   []bool{false, false},
		},
		"1 segment, 5 hops": {
			nsegs:   1,
			nhops:   19,
			segLens: [3]uint8{19, 0, 0},
			inIdxs:  [][2]int{{0, 0}, {0, 3}, {0, 8}, {0, 13}, {0, 16}},
			xover:   []bool{false, false, false, false, false},
		},
		"2 segments, 5 hops": {
			nsegs:   2,
			nhops:   17,
			segLens: [3]uint8{8, 9, 0},
			inIdxs:  [][2]int{{0, 0}, {0, 3}, {1, 8}, {1, 11}, {1, 14}},
			xover:   []bool{false, true, false, false, false},
		},
		"3 segments, 9 hops": {
			nsegs:   3,
			nhops:   37,
			segLens: [3]uint8{6, 16, 15},
			inIdxs: [][2]int{
				{0, 0}, {0, 3}, {1, 6}, {1, 11}, {1, 14}, {1, 19}, {2, 22}, {2, 27}, {2, 32},
			},
			xover: []bool{false, true, false, false, false, true, false, false, false},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		for i := range tc.xover {
			i := i
			s := hummingbird.Base{
				PathMeta: hummingbird.MetaHdr{
					CurrINF: uint8(tc.inIdxs[i][0]),
					CurrHF:  uint8(tc.inIdxs[i][1]),
					SegLen:  tc.segLens,
				},
				NumINF:   tc.nsegs,
				NumLines: tc.nhops,
			}
			t.Run(fmt.Sprintf("%s case %d", name, i+1), func(t *testing.T) {
				t.Parallel()
				assert.Equal(t, tc.xover[i], s.IsXover())
			})
			t.Run(fmt.Sprintf("%s case %d IsFirstAfterXover", name, i+1), func(t *testing.T) {
				t.Parallel()
				firstHopAfterXover := false
				if i > 0 {
					firstHopAfterXover = tc.xover[i-1]
				}
				assert.Equal(t, firstHopAfterXover, s.IsFirstHopAfterXover())
			})
		}
	}
}
