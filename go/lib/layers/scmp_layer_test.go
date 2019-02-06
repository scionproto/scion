// Copyright 2019 ETH Zurich
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

package layers

import (
	"testing"

	"github.com/google/gopacket"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/xtest"
)

func TestExtensionDecodeFromBytes(t *testing.T) {
	type TestCase struct {
		Description   string
		Data          []byte
		ExpectedError bool
		ExpectedSCMP  SCMP
	}
	testCases := []*TestCase{
		{
			Description:   "nil input",
			ExpectedError: true,
		},
		{
			Description:   "truncated header",
			Data:          []byte{1},
			ExpectedError: true,
		},
		{
			Description: "header data, no quotes",
			Data: []byte{0x00, 0x01, 0x02, 0x03, 0x00, 0x18, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x17,
			},
			ExpectedSCMP: SCMP{
				ClassType:            0x00010203,
				Length:               24,
				Checksum:             0x0607,
				Timestamp:            0x08090a0b0c0d0e0f,
				L4ProtoType:          0x16,
				Padding:              0x17,
				InfoBlock:            []byte{},
				CommonHeaderBlock:    []byte{},
				AddressHeaderBlock:   []byte{},
				PathHeaderBlock:      []byte{},
				ExtensionHeaderBlock: []byte{},
				L4Block:              []byte{},
				CustomPayload:        []byte{},
			},
		},
		{
			Description: "packet smaller than total length",
			Data: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x18, 0x19,
			},
			ExpectedError: true,
		},
		{
			Description: "data extends past quotes",
			Data: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x18, 0x19,
			},
			ExpectedSCMP: SCMP{
				Length:               26,
				InfoBlock:            []byte{},
				CommonHeaderBlock:    []byte{},
				AddressHeaderBlock:   []byte{},
				PathHeaderBlock:      []byte{},
				ExtensionHeaderBlock: []byte{},
				L4Block:              []byte{},
				CustomPayload:        []byte{0x18, 0x19},
			},
		},
		{
			Description: "truncated info block",
			Data: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			ExpectedError: true,
		},
		{
			Description: "good info block",
			Data: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			},
			ExpectedSCMP: SCMP{
				Length:         40,
				InfoBlockLines: 2,
				InfoBlock: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				},
				CommonHeaderBlock:    []byte{},
				AddressHeaderBlock:   []byte{},
				PathHeaderBlock:      []byte{},
				ExtensionHeaderBlock: []byte{},
				L4Block:              []byte{},
				CustomPayload:        []byte{},
			},
		},
		{
			Description: "all blocks present, proper length",
			Data: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
				0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
				0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
				0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
				0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
			},
			ExpectedSCMP: SCMP{
				Length:               72,
				InfoBlockLines:       1,
				CommonHeaderLines:    1,
				AddressHeaderLines:   1,
				PathHeaderLines:      1,
				ExtensionHeaderLines: 1,
				L4Lines:              1,
				InfoBlock:            []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
				CommonHeaderBlock:    []byte{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
				AddressHeaderBlock:   []byte{0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
				PathHeaderBlock:      []byte{0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04},
				ExtensionHeaderBlock: []byte{0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05},
				L4Block:              []byte{0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06},
				CustomPayload:        []byte{},
			},
		},
	}
	Convey("", t, func() {
		for _, tc := range testCases {
			Convey(tc.Description, func() {
				var scmp SCMP
				err := scmp.DecodeFromBytes(tc.Data, gopacket.NilDecodeFeedback)
				xtest.SoMsgError("err", err, tc.ExpectedError)
				if !tc.ExpectedError {
					SoMsg("scmp", scmp, ShouldResemble, tc.ExpectedSCMP)
				}
			})
		}
	})
}

func TestSCMPSerializeTo(t *testing.T) {
	type TestCase struct {
		Description      string
		SCMP             SCMP
		SerializeOptions gopacket.SerializeOptions
		ExpectedError    bool
		ExpectedBytes    []byte
		ExpectedLengths  [7]int
	}
	testCases := []*TestCase{
		{
			Description: "empty scmp",
			SCMP:        SCMP{},
			ExpectedBytes: []byte{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
		},
		{
			Description:      "empty scmp with fix lengths",
			SCMP:             SCMP{},
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			ExpectedBytes: []byte{
				0, 0, 0, 0, 0x00, 0x18, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
			ExpectedLengths: [7]int{24, 0, 0, 0, 0, 0, 0},
		},
		{
			Description: "scmp with bad length",
			SCMP:        SCMP{Length: 30},
			ExpectedBytes: []byte{
				0, 0, 0, 0, 0x00, 0x1e, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
			ExpectedLengths: [7]int{30, 0, 0, 0, 0, 0, 0},
		},
		{
			Description: "scmp with header data",
			SCMP: SCMP{
				ClassType:            0x00010203,
				Length:               0x0405,
				Checksum:             0x0607,
				Timestamp:            0x08090a0b0c0d0e0f,
				InfoBlockLines:       42,
				CommonHeaderLines:    43,
				AddressHeaderLines:   44,
				PathHeaderLines:      45,
				ExtensionHeaderLines: 46,
				L4Lines:              47,
				L4ProtoType:          48,
				Padding:              49,
			},
			ExpectedBytes: []byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				42, 43, 44, 45, 46, 47, 48, 49,
			},
			ExpectedLengths: [7]int{0x0405, 42, 43, 44, 45, 46, 47},
		},
		{
			Description: "scmp with bad quote lengths",
			SCMP: SCMP{
				InfoBlockLines:       1,
				CommonHeaderLines:    1,
				AddressHeaderLines:   1,
				PathHeaderLines:      1,
				ExtensionHeaderLines: 1,
				L4Lines:              1,
				InfoBlock:            []byte{1, 2},
				CommonHeaderBlock:    []byte{3, 4},
				AddressHeaderBlock:   []byte{5, 6},
				PathHeaderBlock:      []byte{7, 8},
				ExtensionHeaderBlock: []byte{9, 10},
				L4Block:              []byte{11, 12},
			},
			ExpectedBytes: []byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				1, 1, 1, 1, 1, 1, 0, 0,
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
			},
			ExpectedLengths: [7]int{0, 1, 1, 1, 1, 1, 1},
		},
		{
			Description: "packet too large with fix lengths",
			SCMP: SCMP{
				InfoBlock: make([]byte, 1<<16),
			},
			ExpectedError: true,
		},
		{
			Description:      "non-aligned info block with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				InfoBlock: []byte{1, 2},
			},
			ExpectedError: true,
		},
		{
			Description:      "non-aligned common header quote with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				CommonHeaderBlock: []byte{1, 2},
			},
			ExpectedError: true,
		},
		{
			Description:      "non-aligned address header quote with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				AddressHeaderBlock: []byte{1, 2},
			},
			ExpectedError: true,
		},
		{
			Description:      "non-aligned path header quote with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				PathHeaderBlock: []byte{1, 2},
			},
			ExpectedError: true,
		},
		{
			Description:      "non-aligned extension header quote with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				ExtensionHeaderBlock: []byte{1, 2},
			},
			ExpectedError: true,
		},
		{
			Description:      "non-aligned l4 header quote with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				L4Block: []byte{1, 2},
			},
			ExpectedError: true,
		},
		{
			Description:      "too long info block with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				InfoBlock: make([]byte, 1<<13),
			},
			ExpectedError: true,
		},
		{
			Description:      "too long common header quote with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				CommonHeaderBlock: make([]byte, 1<<13),
			},
			ExpectedError: true,
		},
		{
			Description:      "too long address header quote with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				AddressHeaderBlock: make([]byte, 1<<13),
			},
			ExpectedError: true,
		},
		{
			Description:      "too long path header quote with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				PathHeaderBlock: make([]byte, 1<<13),
			},
			ExpectedError: true,
		},
		{
			Description:      "too long extension header quote with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				ExtensionHeaderBlock: make([]byte, 1<<13),
			},
			ExpectedError: true,
		},
		{
			Description:      "too long l4 header quote with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				L4Block: make([]byte, 1<<13),
			},
			ExpectedError: true,
		},
		{
			Description:      "aligned info block with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				InfoBlock: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
			ExpectedBytes: []byte{
				0, 0, 0, 0, 0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				1, 0, 0, 0, 0, 0, 0, 0,
				1, 2, 3, 4, 5, 6, 7, 8,
			},
			ExpectedLengths: [7]int{32, 1, 0, 0, 0, 0, 0},
		},
		{
			Description:      "aligned common header quote with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				CommonHeaderBlock: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
			ExpectedBytes: []byte{
				0, 0, 0, 0, 0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 1, 0, 0, 0, 0, 0, 0,
				1, 2, 3, 4, 5, 6, 7, 8,
			},
			ExpectedLengths: [7]int{32, 0, 1, 0, 0, 0, 0},
		},
		{
			Description:      "aligned address header quote with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				AddressHeaderBlock: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
			ExpectedBytes: []byte{
				0, 0, 0, 0, 0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 1, 0, 0, 0, 0, 0,
				1, 2, 3, 4, 5, 6, 7, 8,
			},
			ExpectedLengths: [7]int{32, 0, 0, 1, 0, 0, 0},
		},
		{
			Description:      "aligned path header quote with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				PathHeaderBlock: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
			ExpectedBytes: []byte{
				0, 0, 0, 0, 0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 1, 0, 0, 0, 0,
				1, 2, 3, 4, 5, 6, 7, 8,
			},
			ExpectedLengths: [7]int{32, 0, 0, 0, 1, 0, 0},
		},
		{
			Description:      "aligned extension header quote with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				ExtensionHeaderBlock: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
			ExpectedBytes: []byte{
				0, 0, 0, 0, 0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 1, 0, 0, 0,
				1, 2, 3, 4, 5, 6, 7, 8,
			},
			ExpectedLengths: [7]int{32, 0, 0, 0, 0, 1, 0},
		},
		{
			Description:      "aligned L4 header quote with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				L4Block: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
			ExpectedBytes: []byte{
				0, 0, 0, 0, 0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 1, 0, 0,
				1, 2, 3, 4, 5, 6, 7, 8,
			},
			ExpectedLengths: [7]int{32, 0, 0, 0, 0, 0, 1},
		},
		{
			Description: "custom payload",
			SCMP: SCMP{
				CustomPayload: []byte{1, 2},
			},
			ExpectedBytes: []byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				1, 2,
			},
		},
		{
			Description:      "custom payload with fix lengths",
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			SCMP: SCMP{
				CustomPayload: []byte{1, 2},
			},
			ExpectedBytes: []byte{
				0, 0, 0, 0, 0x00, 0x1a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				1, 2,
			},
			ExpectedLengths: [7]int{26, 0, 0, 0, 0, 0, 0},
		},
	}
	Convey("", t, func() {
		for _, tc := range testCases {
			Convey(tc.Description, func() {
				b := gopacket.NewSerializeBuffer()
				err := tc.SCMP.SerializeTo(b, tc.SerializeOptions)
				xtest.SoMsgError("err", err, tc.ExpectedError)
				if !tc.ExpectedError {
					SoMsg("b", b.Bytes(), ShouldResemble, tc.ExpectedBytes)

					lengths := [7]int{
						int(tc.SCMP.Length),
						int(tc.SCMP.InfoBlockLines), int(tc.SCMP.CommonHeaderLines),
						int(tc.SCMP.AddressHeaderLines), int(tc.SCMP.PathHeaderLines),
						int(tc.SCMP.ExtensionHeaderLines), int(tc.SCMP.L4Lines),
					}
					SoMsg("updated length field", lengths, ShouldEqual, tc.ExpectedLengths)
				}
			})
		}
	})
}
