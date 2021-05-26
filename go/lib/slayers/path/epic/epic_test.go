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

package epic_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/slayers/path/epic"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
)

var (
	// Values for the SCION subheader are taken from scion_test.go and raw_test.go.
	rawScionPath = []byte(
		"\x00\x00\x20\x80\x00\x00\x01\x11\x00\x00\x01\x00\x01\x00\x02\x22\x00\x00" +
			"\x01\x00\x00\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x3f\x00" +
			"\x03\x00\x02\x01\x02" +
			"\x03\x04\x05\x06\x00\x3f\x00\x00\x00\x02\x01\x02\x03\x04\x05\x06\x00" +
			"\x3f\x00\x01\x00\x00" +
			"\x01\x02\x03\x04\x05\x06")
	rawScionReversePath = []byte(
		"\x43\x00\x20\x80\x00\x00\x02\x22\x00\x00\x01\x00\x01\x00\x01\x11\x00\x00" +
			"\x01\x00\x00\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x3f\x00" +
			"\x00\x00\x02\x01\x02" +
			"\x03\x04\x05\x06\x00\x3f\x00\x03\x00\x02\x01\x02\x03\x04\x05\x06\x00" +
			"\x3f\x00\x01\x00\x00" +
			"\x01\x02\x03\x04\x05\x06")
	rawEpicPath = append([]byte("\x00\x00\x00\x01\x02\x00\x00\x03\x01\x02\x03\x04\x05\x06\x07\x08"),
		rawScionPath...)
	decodedScionPath = &scion.Raw{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrINF: 0,
				CurrHF:  0,
				SegLen:  [3]uint8{2, 2, 0},
			},
			NumINF:  2,
			NumHops: 4,
		},
		Raw: rawScionPath,
	}
)

func TestSerialize(t *testing.T) {
	testCases := map[string]struct {
		Path       epic.Path
		Serialized []byte
		errorFunc  assert.ErrorAssertionFunc
	}{
		"Basic": {
			Path: epic.Path{
				PktID: epic.PktID{
					Timestamp: 1,
					Counter:   0x02000003,
				},
				PHVF: []byte{1, 2, 3, 4},
				LHVF: []byte{5, 6, 7, 8},
				ScionPath: &scion.Raw{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrINF: 0,
							CurrHF:  0,
							SegLen:  [3]uint8{2, 2, 0},
						},
						NumINF:  2,
						NumHops: 4,
					},
					Raw: rawScionPath,
				},
			},
			Serialized: rawEpicPath,
			errorFunc:  assert.NoError,
		},
		"HVF too short": {
			Path: epic.Path{
				PktID: epic.PktID{
					Timestamp: 1,
					Counter:   0x02000003,
				},
				PHVF: []byte{1, 2, 3},
				LHVF: []byte{5, 6, 7, 8},
				ScionPath: &scion.Raw{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrINF: 0,
							CurrHF:  0,
							SegLen:  [3]uint8{2, 2, 0},
						},
						NumINF:  2,
						NumHops: 4,
					},
					Raw: rawScionPath,
				},
			},
			errorFunc: assert.Error,
		},
		"HVF too long": {
			Path: epic.Path{
				PktID: epic.PktID{
					Timestamp: 1,
					Counter:   0x02000003,
				},
				PHVF: []byte{1, 2, 3, 4},
				LHVF: []byte{5, 6, 7, 8, 9},
				ScionPath: &scion.Raw{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrINF: 0,
							CurrHF:  0,
							SegLen:  [3]uint8{2, 2, 0},
						},
						NumINF:  2,
						NumHops: 4,
					},
					Raw: rawScionPath,
				},
			},
			errorFunc: assert.Error,
		},
		"SCION path nil": {
			Path: epic.Path{
				PktID: epic.PktID{
					Timestamp: 1,
					Counter:   0x02000003,
				},
				PHVF: []byte{1, 2, 3, 4},
				LHVF: []byte{5, 6, 7, 8},
			},
			errorFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			b := make([]byte, len(tc.Serialized))
			err := tc.Path.SerializeTo(b)
			tc.errorFunc(t, err)
			if err == nil {
				assert.Equal(t, tc.Serialized, b)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	testCases := map[string]struct {
		Path       epic.Path
		Serialized []byte
	}{
		"Basic": {
			Path: epic.Path{
				PktID: epic.PktID{
					Timestamp: 1,
					Counter:   0x02000003,
				},
				PHVF:      []byte{1, 2, 3, 4},
				LHVF:      []byte{5, 6, 7, 8},
				ScionPath: decodedScionPath,
			},
			Serialized: rawEpicPath,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			got := epic.Path{}
			assert.NoError(t, got.DecodeFromBytes(tc.Serialized))
			assert.Equal(t, tc.Path, got)
		})
	}
}

func TestReverse(t *testing.T) {
	testCases := map[string]struct {
		Path         *epic.Path
		PathReversed *epic.Path
	}{
		"Basic reverse": {
			Path: &epic.Path{
				PktID: epic.PktID{
					Timestamp: 1,
					Counter:   0x02000003,
				},
				PHVF: []byte{1, 2, 3, 4},
				LHVF: []byte{5, 6, 7, 8},
				ScionPath: &scion.Raw{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrINF: 0,
							CurrHF:  0,
							SegLen:  [3]uint8{2, 2, 0},
						},
						NumINF:  2,
						NumHops: 4,
					},
					Raw: append([]byte(nil), rawScionPath...), // copy of rawScionPath
				},
			},
			PathReversed: &epic.Path{
				PktID: epic.PktID{
					Timestamp: 1,
					Counter:   0x02000003,
				},
				PHVF: []byte{1, 2, 3, 4},
				LHVF: []byte{5, 6, 7, 8},
				ScionPath: &scion.Raw{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrINF: 1,
							CurrHF:  3,
							SegLen:  [3]uint8{2, 2, 0},
						},
						NumINF:  2,
						NumHops: 4,
					},
					Raw: append([]byte(nil), rawScionReversePath...), // copy of rawScionReversePath
				},
			},
		},
		"Reverse a reversed path": {
			Path: &epic.Path{
				PktID: epic.PktID{
					Timestamp: 1,
					Counter:   0x02000003,
				},
				PHVF: []byte{1, 2, 3, 4},
				LHVF: []byte{5, 6, 7, 8},
				ScionPath: &scion.Raw{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrINF: 1,
							CurrHF:  3,
							SegLen:  [3]uint8{2, 2, 0},
						},
						NumINF:  2,
						NumHops: 4,
					},
					Raw: append([]byte(nil), rawScionReversePath...), // copy of rawScionReversePath
				},
			},
			PathReversed: &epic.Path{
				PktID: epic.PktID{
					Timestamp: 1,
					Counter:   0x02000003,
				},
				PHVF: []byte{1, 2, 3, 4},
				LHVF: []byte{5, 6, 7, 8},
				ScionPath: &scion.Raw{
					Base: scion.Base{
						PathMeta: scion.MetaHdr{
							CurrINF: 0,
							CurrHF:  0,
							SegLen:  [3]uint8{2, 2, 0},
						},
						NumINF:  2,
						NumHops: 4,
					},
					Raw: append([]byte(nil), rawScionPath...), // copy of rawScionPath
				},
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			got, err := tc.Path.Reverse()
			assert.NoError(t, err)
			assert.Equal(t, tc.PathReversed, got)
		})
	}
}

func TestSerializePktID(t *testing.T) {
	testCasesSerialize := map[string]struct {
		PktID      epic.PktID
		Serialized []byte
	}{
		"Basic": {
			PktID: epic.PktID{
				Timestamp: 1,
				Counter:   0x02000003,
			},
			Serialized: []byte{0, 0, 0, 1, 2, 0, 0, 3},
		},
		"Max. timestamp": {
			PktID: epic.PktID{
				Timestamp: ^uint32(0),
				Counter:   0x02000003,
			},
			Serialized: []byte{255, 255, 255, 255, 2, 0, 0, 3},
		},
	}

	for name, tc := range testCasesSerialize {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			bNew := make([]byte, epic.PktIDLen)
			tc.PktID.SerializeTo(bNew)
			assert.Equal(t, tc.Serialized, bNew)
		})
	}
}

func TestDecodePktID(t *testing.T) {
	testCases := map[string]struct {
		PktID      epic.PktID
		Serialized []byte
	}{
		"Basic": {
			PktID: epic.PktID{
				Timestamp: 1,
				Counter:   0x02000003,
			},
			Serialized: []byte{0, 0, 0, 1, 2, 0, 0, 3},
		},
		"Max. timestamp": {
			PktID: epic.PktID{
				Timestamp: ^uint32(0),
				Counter:   0x02000003,
			},
			Serialized: []byte{255, 255, 255, 255, 2, 0, 0, 3},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			pktIDNew := epic.PktID{}
			pktIDNew.DecodeFromBytes(tc.Serialized)
			assert.Equal(t, tc.PktID, pktIDNew)
		})
	}
}
