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
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
)

var infoFields = []path.InfoField{
	{
		Peer:      false,
		ConsDir:   false,
		SegID:     0x111,
		Timestamp: 0x100,
	},
	{
		Peer:      false,
		ConsDir:   true,
		SegID:     0x222,
		Timestamp: 0x100,
	},
}

var flyoverFields = []hummingbird.FlyoverHopField{
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 1,
			ConsEgress:  0,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
		Flyover:      true,
		ResID:        0,
		Bw:           4,
		ResStartTime: 2,
		Duration:     1,
	},
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 3,
			ConsEgress:  2,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
	},
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 0,
			ConsEgress:  2,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
	},
	{
		HopField: path.HopField{
			ExpTime:     63,
			ConsIngress: 1,
			ConsEgress:  0,
			Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		},
		Flyover:      true,
		ResID:        0,
		Bw:           4,
		ResStartTime: 0,
		Duration:     1,
	},
}

var decodedPaths = []*hummingbird.Decoded{
	{
		Base: hummingbird.Base{
			PathMeta: hummingbird.MetaHdr{
				CurrINF:   0,
				CurrHF:    0,
				SegLen:    [3]uint8{8, 8, 0},
				BaseTS:    808,
				HighResTS: 1234,
			},
			NumINF:   2,
			NumLines: 16,
		},
		InfoFields:     infoFields,
		HopFields:      flyoverFields,
		FirstHopPerSeg: [2]uint8{2, 4},
	},
	{
		Base: hummingbird.Base{
			PathMeta: hummingbird.MetaHdr{
				CurrINF:   0,
				CurrHF:    0,
				SegLen:    [3]uint8{8, 6, 0},
				BaseTS:    808,
				HighResTS: 1234,
			},
			NumINF:   2,
			NumLines: 14,
		},
		InfoFields: infoFields,
		HopFields: []hummingbird.FlyoverHopField{
			{
				HopField: path.HopField{
					ExpTime:     63,
					ConsIngress: 1,
					ConsEgress:  0,
					Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
				},
				Flyover:      true,
				ResID:        0,
				Bw:           4,
				ResStartTime: 2,
				Duration:     1,
			},
			{
				HopField: path.HopField{
					ExpTime:     63,
					ConsIngress: 3,
					ConsEgress:  2,
					Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
				},
			},
			{
				HopField: path.HopField{
					ExpTime:     63,
					ConsIngress: 0,
					ConsEgress:  2,
					Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
				},
			},
			{
				HopField: path.HopField{
					ExpTime:     63,
					ConsIngress: 1,
					ConsEgress:  0,
					Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
				},
			},
		},

		FirstHopPerSeg: [2]uint8{2, 4},
	},
}

var decodedBytes = [][]byte{
	[]byte("\x00\x02\x04\x00\x00\x00\x03\x28\x00\x00\x04\xd2" +
		"\x00\x00\x01\x11\x00\x00\x01\x00\x01\x00\x02\x22\x00\x00\x01\x00" +
		"\x80\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x00\x00\x04\x00\x02\x00\x01" +
		"\x00\x3f\x00\x03\x00\x02\x01\x02\x03\x04\x05\x06" +
		"\x00\x3f\x00\x00\x00\x02\x01\x02\x03\x04\x05\x06" +
		"\x80\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x00\x00\x04\x00\x00\x00\x01"),

	[]byte("\x00\x02\x03\x00\x00\x00\x03\x28\x00\x00\x04\xd2" +
		"\x00\x00\x01\x11\x00\x00\x01\x00\x01\x00\x02\x22\x00\x00\x01\x00" +
		"\x80\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x00\x00\x04\x00\x02\x00\x01" +
		"\x00\x3f\x00\x03\x00\x02\x01\x02\x03\x04\x05\x06" +
		"\x00\x3f\x00\x00\x00\x02\x01\x02\x03\x04\x05\x06" +
		"\x00\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06"),
}

var pathReverseTestCases = map[string]struct {
	input    hbirdPathCase
	want     hbirdPathCase
	inIdxs   [][2]int
	wantIdxs [][2]int
}{
	"1 segment, 2 hops": {
		input:    hbirdPathCase{[]bool{true}, [][][]uint16{{{11, 0}, {12, 1}}}},
		want:     hbirdPathCase{[]bool{false}, [][][]uint16{{{12, 0}, {11, 0}}}},
		inIdxs:   [][2]int{{0, 0}, {0, 3}},
		wantIdxs: [][2]int{{0, 3}, {0, 0}},
	},
	"1 segment, 5 hops": {
		input: hbirdPathCase{[]bool{true},
			[][][]uint16{{{11, 1}, {12, 1}, {13, 0}, {14, 1}, {15, 0}}}},
		want: hbirdPathCase{[]bool{false},
			[][][]uint16{{{15, 0}, {14, 0}, {13, 0}, {12, 0}, {11, 0}}}},
		inIdxs:   [][2]int{{0, 0}, {0, 5}, {0, 10}, {0, 13}, {0, 18}},
		wantIdxs: [][2]int{{0, 12}, {0, 9}, {0, 6}, {0, 3}, {0, 0}},
	},
	"2 segments, 5 hops": {
		input: hbirdPathCase{[]bool{true, false},
			[][][]uint16{{{11, 0}, {12, 0}}, {{13, 1}, {14, 1}, {15, 0}}}},
		want: hbirdPathCase{[]bool{true, false},
			[][][]uint16{{{15, 0}, {14, 0}, {13, 0}}, {{12, 0}, {11, 0}}}},
		inIdxs:   [][2]int{{0, 0}, {0, 3}, {1, 6}, {1, 11}, {1, 16}},
		wantIdxs: [][2]int{{1, 12}, {1, 9}, {0, 6}, {0, 3}, {0, 0}},
	},
	"3 segments, 9 hops": {
		input: hbirdPathCase{
			[]bool{true, false, false},
			[][][]uint16{
				{{11, 1}, {12, 0}},
				{{13, 0}, {14, 1}, {15, 1}, {16, 0}},
				{{17, 0}, {18, 1}, {19, 1}},
			},
		},
		want: hbirdPathCase{
			[]bool{true, true, false},
			[][][]uint16{
				{{19, 0}, {18, 0}, {17, 0}},
				{{16, 0}, {15, 0}, {14, 0}, {13, 0}},
				{{12, 0}, {11, 0}},
			},
		},
		inIdxs: [][2]int{
			{0, 0}, {0, 5}, {1, 8}, {1, 11}, {1, 16}, {1, 21}, {2, 24}, {2, 27}, {2, 32},
		},
		wantIdxs: [][2]int{
			{2, 24}, {2, 21}, {1, 18}, {1, 15}, {1, 12}, {1, 9}, {0, 6}, {0, 3}, {0, 0},
		},
	},
}

type hbirdPathCase struct {
	infos []bool
	hops  [][][]uint16
}
