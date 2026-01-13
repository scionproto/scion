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

	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

func TestDecodedSerializeHbird(t *testing.T) {
	for i := range decodedPaths {
		b := make([]byte, decodedPaths[i].Len())
		assert.NoError(t, decodedPaths[i].SerializeTo(b))
		assert.Equal(t, decodedBytes[i], b)
	}
}

func TestDecodeFromBytesHbird(t *testing.T) {
	s := &hummingbird.Decoded{}
	for i := range decodedPaths {
		assert.NoError(t, s.DecodeFromBytes(decodedBytes[i]))
		assert.Equal(t, decodedPaths[i], s)
	}
}

func TestSerializeAndBack(t *testing.T) {
	for i := range decodedPaths {
		buff := make([]byte, decodedPaths[i].Len())
		assert.NoError(t, decodedPaths[i].SerializeTo(buff))
		s := &hummingbird.Decoded{}
		assert.NoError(t, s.DecodeFromBytes(buff))
		assert.Equal(t, decodedPaths[i], s)
	}
}

func TestDecodedDecodeFromBytesNoFlyovers(t *testing.T) {
	// p is the scion decoded path we would observe using the Tiny topology of the
	// topology generator, when going from 111 to 112. This is one up segment with 2 hops, followed
	// by a down segment with two hops as well. There is a cross over at core 110 gluing both.
	p := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				SegLen: [3]uint8{2, 2, 0},
			},
			NumINF:  2,
			NumHops: 4,
		},
		InfoFields: []path.InfoField{
			{}, // up
			{}, // down
		},
		HopFields: []path.HopField{
			{}, // 111: 0->41 up
			{}, // 110: 1->0  up
			{}, // 110: 0->2  down
			{}, // 112: 1->0  down
		},
	}

	// Create a hummingbird path from the scion one.
	hbird := &hummingbird.Decoded{}
	hbird.ConvertFromScionDecoded(*p) // SegLen will be [6,6,0] after this

	// Check the hummingbird path is correct by serializing and deserializing it.
	buf := make([]byte, hbird.Len())
	err := hbird.SerializeTo(buf)
	assert.NoError(t, err)
	// Deserialize.
	hbird = &hummingbird.Decoded{}
	err = hbird.DecodeFromBytes(buf)
	assert.NoError(t, err)
}

func TestDecodedReverseHbird(t *testing.T) {
	for name, tc := range pathReverseTestCases {
		name, tc := name, tc
		for i := range tc.inIdxs {
			i := i
			t.Run(fmt.Sprintf("%s case %d", name, i+1), func(t *testing.T) {
				t.Parallel()
				inputPath := mkDecodedHbirdPath(t, tc.input, uint8(tc.inIdxs[i][0]),
					uint8(tc.inIdxs[i][1]))
				wantPath := mkDecodedHbirdPath(t, tc.want, uint8(tc.wantIdxs[i][0]),
					uint8(tc.wantIdxs[i][1]))
				revPath, err := inputPath.Reverse()
				assert.NoError(t, err)
				assert.Equal(t, wantPath, revPath)
			})
		}
	}
}

func TestEmptyDecodedReverse(t *testing.T) {
	emptyDecodedTestPath := &hummingbird.Decoded{
		Base:       hummingbird.Base{},
		InfoFields: []path.InfoField{},
		HopFields:  []hummingbird.FlyoverHopField{},
	}
	_, err := emptyDecodedTestPath.Reverse()
	assert.Error(t, err)
}

func TestDecodedToRaw(t *testing.T) {
	raw, err := decodedPaths[0].ToRaw()
	assert.NoError(t, err)
	assert.Equal(t, rawHbirdTestPath, raw)
}

func TestInfIndexForHFIndex(t *testing.T) {
	cases := map[string]struct {
		path     hummingbird.Decoded
		expected []uint8 // the INF indices of each hop field in the test case
	}{
		"empty": {
			path: hummingbird.Decoded{
				Base: hummingbird.Base{
					PathMeta: hummingbird.MetaHdr{
						SegLen: [3]uint8{0, 0, 0},
					},
				},
			},
		},
		"one_segment_o": {
			path: hummingbird.Decoded{
				Base: hummingbird.Base{
					PathMeta: hummingbird.MetaHdr{
						SegLen: [3]uint8{3, 0, 0},
					},
				},
				HopFields: []hummingbird.FlyoverHopField{
					{Flyover: false},
				},
			},
			expected: []uint8{0},
		},
		// one_segment_oxx means there is one segment with three hops, first is not flyover,
		// second and third are.
		"one_segment_oxx": {
			path: hummingbird.Decoded{
				Base: hummingbird.Base{
					PathMeta: hummingbird.MetaHdr{
						SegLen: [3]uint8{13, 0, 0},
					},
				},
				HopFields: []hummingbird.FlyoverHopField{
					{Flyover: false},
					{Flyover: true},
					{Flyover: true},
				},
			},
			expected: []uint8{0, 0, 0},
		},
		"two_segments_o_oxx": {
			path: hummingbird.Decoded{
				Base: hummingbird.Base{
					PathMeta: hummingbird.MetaHdr{
						SegLen: [3]uint8{3, 13, 0},
					},
				},
				HopFields: []hummingbird.FlyoverHopField{
					{Flyover: false},
					{Flyover: false},
					{Flyover: true},
					{Flyover: true},
				},
			},
			expected: []uint8{0, 1, 1, 1},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			for i := range tc.path.HopFields {
				got := tc.path.InfIndexForHFIndex(uint8(i))
				assert.Equal(t, tc.expected[i], got)
			}
			assert.Panics(t, func() {
				tc.path.InfIndexForHFIndex(uint8(len(tc.path.HopFields)) + 1)
			})
		})
	}
}

func mkDecodedHbirdPath(
	t *testing.T,
	pcase hbirdPathCase,
	infIdx uint8,
	hopIdx uint8,
) *hummingbird.Decoded {
	t.Helper()
	s := &hummingbird.Decoded{
		Base: hummingbird.Base{
			PathMeta: hummingbird.MetaHdr{
				CurrINF:   infIdx,
				CurrHF:    hopIdx,
				BaseTS:    14,
				HighResTS: 15,
			},
		},
	}
	for _, dir := range pcase.infos {
		s.InfoFields = append(s.InfoFields, path.InfoField{ConsDir: dir})
	}
	i := 0
	for j, hops := range pcase.hops {
		for _, hop := range hops {
			isFlyover := hop[1] == 1
			s.HopFields = append(s.HopFields,
				hummingbird.FlyoverHopField{
					HopField: path.HopField{
						ConsIngress: hop[0],
						ConsEgress:  hop[0],
						Mac:         [6]byte{1, 2, 3, 4, 5, 6}},
					Flyover:  isFlyover,
					Duration: 2,
				})
			if isFlyover {
				i += 5
				s.PathMeta.SegLen[j] += 5
			} else {
				i += 3
				s.PathMeta.SegLen[j] += 3
			}
		}
	}
	s.NumINF = len(pcase.infos)
	s.NumLines = i

	return s
}
