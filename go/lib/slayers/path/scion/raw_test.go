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
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
)

var rawTestPath = &scion.Raw{
	Base: scion.Base{
		PathMeta: scion.MetaHdr{
			CurrINF: 0,
			CurrHF:  0,
			SegLen:  [3]uint8{2, 2, 0},
		},
		NumINF:  2,
		NumHops: 4,
	},
	Raw: rawPath,
}

func TestRawSerialize(t *testing.T) {
	b := make([]byte, rawTestPath.Len())
	assert.NoError(t, rawTestPath.SerializeTo(b))
	assert.Equal(t, rawPath, b)
}

func TestRawDecodeFromBytes(t *testing.T) {
	s := &scion.Raw{}
	assert.NoError(t, s.DecodeFromBytes(rawPath))
	assert.Equal(t, rawTestPath, s)
}

func TestRawSerliazeDecode(t *testing.T) {
	b := make([]byte, rawTestPath.Len())
	assert.NoError(t, rawTestPath.SerializeTo(b))
	s := &scion.Raw{}
	assert.NoError(t, s.DecodeFromBytes(b))
	assert.Equal(t, rawTestPath, s)
}

func TestRawReverse(t *testing.T) {
	for name, tc := range pathReverseCases {
		name, tc := name, tc
		for i := range tc.inIdxs {
			i := i
			t.Run(fmt.Sprintf("%s case %d", name, i+1), func(t *testing.T) {
				t.Parallel()
				input := mkRawPath(t, tc.input, uint8(tc.inIdxs[i][0]), uint8(tc.inIdxs[i][1]))
				want := mkRawPath(t, tc.want, uint8(tc.wantIdxs[i][0]), uint8(tc.wantIdxs[i][1]))
				revPath, err := input.Reverse()
				assert.NoError(t, err)
				assert.Equal(t, want, revPath)
			})
		}
	}
}

func TestRawToDecoded(t *testing.T) {
	decoded, err := rawTestPath.ToDecoded()
	assert.NoError(t, err)
	assert.Equal(t, decodedTestPath, decoded)
}

func TestGetInfoField(t *testing.T) {
	testCases := map[string]struct {
		idx       int
		want      *path.InfoField
		errorFunc assert.ErrorAssertionFunc
	}{
		"first info": {
			idx:       0,
			want:      testInfoFields[0],
			errorFunc: assert.NoError,
		},
		"second info": {
			idx:       1,
			want:      testInfoFields[1],
			errorFunc: assert.NoError,
		},
		"out of bounds": {
			idx:       2,
			want:      nil,
			errorFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := rawTestPath.GetInfoField(tc.idx)
			tc.errorFunc(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGetHopField(t *testing.T) {
	testCases := map[string]struct {
		idx       int
		want      *path.HopField
		errorFunc assert.ErrorAssertionFunc
	}{
		"first hop": {
			idx:       0,
			want:      testHopFields[0],
			errorFunc: assert.NoError,
		},
		"third hop": {
			idx:       2,
			want:      testHopFields[2],
			errorFunc: assert.NoError,
		},
		"out of bounds": {
			idx:       4,
			want:      nil,
			errorFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := rawTestPath.GetHopField(tc.idx)
			tc.errorFunc(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSetInfoField(t *testing.T) {
	testCases := map[string]struct {
		idx       int
		want      *path.InfoField
		errorFunc assert.ErrorAssertionFunc
	}{
		"first info": {
			idx:       0,
			want:      testInfoFields[1],
			errorFunc: assert.NoError,
		},
		"second info": {
			idx:       1,
			want:      testInfoFields[0],
			errorFunc: assert.NoError,
		},
		"out of bounds": {
			idx:       2,
			want:      nil,
			errorFunc: assert.Error,
		},
		"nil info": {
			idx:       0,
			want:      nil,
			errorFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw := &scion.Raw{}
			require.NoError(t, raw.DecodeFromBytes(rawPath))

			err := raw.SetInfoField(tc.want, tc.idx)
			tc.errorFunc(t, err)
			if err != nil {
				return
			}
			got, err := raw.GetInfoField(tc.idx)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSetHopField(t *testing.T) {
	testCases := map[string]struct {
		idx       int
		want      *path.HopField
		errorFunc assert.ErrorAssertionFunc
	}{
		"first hop": {
			idx:       0,
			want:      testHopFields[3],
			errorFunc: assert.NoError,
		},
		"third hop": {
			idx:       2,
			want:      testHopFields[0],
			errorFunc: assert.NoError,
		},
		"out of bounds": {
			idx:       4,
			want:      nil,
			errorFunc: assert.Error,
		},
		"nil info": {
			idx:       0,
			want:      nil,
			errorFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw := &scion.Raw{}
			require.NoError(t, raw.DecodeFromBytes(rawPath))

			err := raw.SetHopField(tc.want, tc.idx)
			tc.errorFunc(t, err)
			if err != nil {
				return
			}
			got, err := raw.GetHopField(tc.idx)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func mkRawPath(t *testing.T, pcase pathCase, infIdx, hopIdx uint8) *scion.Raw {
	t.Helper()
	decoded := mkDecodedPath(t, pcase, infIdx, hopIdx)
	raw, err := decoded.ToRaw()
	require.NoError(t, err)
	return raw
}

func TestPenultimateHop(t *testing.T) {
	testCases := map[*scion.Raw]bool{
		createScionPath(0, 2): true,
		createScionPath(1, 2): false,
		createScionPath(2, 2): false,
		createScionPath(5, 7): true,
		createScionPath(6, 7): false,
		createScionPath(7, 7): false,
	}
	for scionRaw, want := range testCases {
		got := scionRaw.IsPenultimateHop()
		assert.Equal(t, want, got)
	}
}

func TestLastHop(t *testing.T) {
	testCases := map[*scion.Raw]bool{
		createScionPath(0, 2): false,
		createScionPath(1, 2): true,
		createScionPath(2, 2): false,
		createScionPath(5, 7): false,
		createScionPath(6, 7): true,
		createScionPath(7, 7): false,
	}
	for scionRaw, want := range testCases {
		got := scionRaw.IsLastHop()
		assert.Equal(t, want, got)
	}
}

func createScionPath(currHF uint8, numHops int) *scion.Raw {
	scionRaw := &scion.Raw{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: currHF,
			},
			NumHops: numHops,
		},
	}
	return scionRaw
}
