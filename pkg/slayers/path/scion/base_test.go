// Copyright 2020 Anapaya Systems
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

package scion_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

func TestPathMetaDecode(t *testing.T) {
	testCases := map[string]struct {
		raw       []byte
		assertErr assert.ErrorAssertionFunc
		expected  scion.MetaHdr
	}{
		"nil": {
			raw:       nil,
			assertErr: assert.Error,
		},
		"short": {
			raw:       []byte{1, 2, 3},
			assertErr: assert.Error,
		},
		"ok": {
			raw: []byte{0x42, 0x0, 0x31, 0x05},
			expected: scion.MetaHdr{
				CurrINF: 1,
				CurrHF:  2,
				SegLen:  [3]uint8{3, 4, 5},
			},
			assertErr: assert.NoError,
		},
		"limits": {
			raw: []byte{0xff, 0x03, 0xff, 0xff},
			expected: scion.MetaHdr{
				CurrINF: 3, // nonsensical but can be represented
				CurrHF:  63,
				SegLen:  [3]uint8{63, 63, 63},
			},
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var actual scion.MetaHdr
			err := actual.DecodeFromBytes(tc.raw)
			tc.assertErr(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestPathBaseDecode(t *testing.T) {
	testCases := map[string]struct {
		raw       []byte
		assertErr assert.ErrorAssertionFunc
		expected  scion.Base
	}{
		"nil": {
			raw:       nil,
			assertErr: assert.Error,
		},
		"short": {
			raw:       []byte{1, 2, 3},
			assertErr: assert.Error,
		},
		"three segments": {
			raw: []byte{0x42, 0x0, 0x31, 0x05},
			expected: scion.Base{
				PathMeta: scion.MetaHdr{
					CurrINF: 1,
					CurrHF:  2,
					SegLen:  [3]uint8{3, 4, 5},
				},
				NumINF:  3,
				NumHops: 3 + 4 + 5,
			},
			assertErr: assert.NoError,
		},
		"two segments": {
			raw: []byte{0x42, 0x0, 0x31, 0x00},
			expected: scion.Base{
				PathMeta: scion.MetaHdr{
					CurrINF: 1,
					CurrHF:  2,
					SegLen:  [3]uint8{3, 4, 0},
				},
				NumINF:  2,
				NumHops: 3 + 4,
			},
			assertErr: assert.NoError,
		},
		"one segment": {
			raw: []byte{0x02, 0x0, 0x30, 0x00},
			expected: scion.Base{
				PathMeta: scion.MetaHdr{
					CurrINF: 0,
					CurrHF:  2,
					SegLen:  [3]uint8{3, 0, 0},
				},
				NumINF:  1,
				NumHops: 3,
			},
			assertErr: assert.NoError,
		},
		"no segment": {
			raw:       []byte{0x00, 0x00, 0x00, 0x00},
			assertErr: assert.Error,
		},
		"one segment, currINF out of range": {
			raw:       []byte{0x42, 0x0, 0x30, 0x00}, // CurrINF is 1
			assertErr: assert.Error,
		},
		"two segments, currINF out of range": {
			raw:       []byte{0x82, 0x0, 0x31, 0x00}, // CurrINF is 2
			assertErr: assert.Error,
		},
		"one segment, currHF out of range": {
			raw:       []byte{0x03, 0x0, 0x30, 0x00}, // CurrHF is 3 which is >= SegLen[0]
			assertErr: assert.Error,
		},
		"two segments, currHF out of range": {
			raw:       []byte{0x07, 0x0, 0x31, 0x00}, // CurrHF is 7 which is >= 3+4
			assertErr: assert.Error,
		},
		"impossible curr inf": {
			raw:       []byte{0xc0, 0x03, 0xff, 0xff}, // CurrInf is 3
			assertErr: assert.Error,
		},
		"non-zero seglen after zero at 0": {
			raw:       []byte{0x42, 0x00, 0x0f, 0xff},
			assertErr: assert.Error,
		},
		"non-zero seglen after zero at 1": {
			raw:       []byte{0x42, 0x03, 0xf0, 0x3f},
			assertErr: assert.Error,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var actual scion.Base
			err := actual.DecodeFromBytes(tc.raw)
			tc.assertErr(t, err)
			if err == nil {
				assert.Equal(t, tc.expected, actual)
			}
		})
	}
}

func TestIncPath(t *testing.T) {
	testCases := map[string]struct {
		nsegs, nhops     int
		segLens          [3]uint8
		inIdxs, wantIdxs [][2]int
	}{
		"1 segment, 2 hops": {
			nsegs:    1,
			nhops:    2,
			segLens:  [3]uint8{2, 0, 0},
			inIdxs:   [][2]int{{0, 0}, {0, 1}},
			wantIdxs: [][2]int{{0, 1}, {0, 0}},
		},
		"1 segment, 5 hops": {
			nsegs:    1,
			nhops:    5,
			segLens:  [3]uint8{5, 0, 0},
			inIdxs:   [][2]int{{0, 0}, {0, 1}, {0, 2}, {0, 3}, {0, 4}},
			wantIdxs: [][2]int{{0, 1}, {0, 2}, {0, 3}, {0, 4}, {0, 0}},
		},
		"2 segments, 5 hops": {
			nsegs:    2,
			nhops:    5,
			segLens:  [3]uint8{2, 3, 0},
			inIdxs:   [][2]int{{0, 0}, {0, 1}, {1, 2}, {1, 3}, {1, 4}},
			wantIdxs: [][2]int{{0, 1}, {1, 2}, {1, 3}, {1, 4}, {0, 0}},
		},
		"3 segments, 9 hops": {
			nsegs:   3,
			nhops:   9,
			segLens: [3]uint8{2, 4, 3},
			inIdxs: [][2]int{
				{0, 0}, {0, 1}, {1, 2}, {1, 3}, {1, 4}, {1, 5}, {2, 6}, {2, 7}, {2, 8},
			},
			wantIdxs: [][2]int{
				{0, 1}, {1, 2}, {1, 3}, {1, 4}, {1, 5}, {2, 6}, {2, 7}, {2, 8}, {0, 0},
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		for i := range tc.inIdxs {
			i := i
			t.Run(fmt.Sprintf("%s case %d", name, i+1), func(t *testing.T) {
				t.Parallel()
				s := scion.Base{
					PathMeta: scion.MetaHdr{
						CurrINF: uint8(tc.inIdxs[i][0]),
						CurrHF:  uint8(tc.inIdxs[i][1]),
						SegLen:  tc.segLens,
					},
					NumINF:  tc.nsegs,
					NumHops: tc.nhops,
				}
				err := s.IncPath()
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
			nhops:   2,
			segLens: [3]uint8{2, 0, 0},
			inIdxs:  [][2]int{{0, 0}, {0, 1}},
			xover:   []bool{false, false},
		},
		"1 segment, 5 hops": {
			nsegs:   1,
			nhops:   5,
			segLens: [3]uint8{5, 0, 0},
			inIdxs:  [][2]int{{0, 0}, {0, 1}, {0, 2}, {0, 3}, {0, 4}},
			xover:   []bool{false, false, false, false, false},
		},
		"2 segments, 5 hops": {
			nsegs:   2,
			nhops:   5,
			segLens: [3]uint8{2, 3, 0},
			inIdxs:  [][2]int{{0, 0}, {0, 1}, {1, 2}, {1, 3}, {1, 4}},
			xover:   []bool{false, true, false, false, false},
		},
		"3 segments, 9 hops": {
			nsegs:   3,
			nhops:   9,
			segLens: [3]uint8{2, 4, 3},
			inIdxs: [][2]int{
				{0, 0}, {0, 1}, {1, 2}, {1, 3}, {1, 4}, {1, 5}, {2, 6}, {2, 7}, {2, 8},
			},
			xover: []bool{false, true, false, false, false, true, false, false, false},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		for i := range tc.xover {
			i := i
			t.Run(fmt.Sprintf("%s case %d", name, i+1), func(t *testing.T) {
				t.Parallel()
				s := scion.Base{
					PathMeta: scion.MetaHdr{
						CurrINF: uint8(tc.inIdxs[i][0]),
						CurrHF:  uint8(tc.inIdxs[i][1]),
						SegLen:  tc.segLens,
					},
					NumINF:  tc.nsegs,
					NumHops: tc.nhops,
				}
				assert.Equal(t, tc.xover[i], s.IsXover())
			})
		}
	}
}
