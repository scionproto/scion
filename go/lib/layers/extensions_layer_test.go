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
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtensionDecodeFromBytes(t *testing.T) {
	type TestCase struct {
		Description       string
		Data              []byte
		ExpectedError     bool
		ExpectedExtension Extension
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
			Description:   "truncated extension body",
			Data:          []byte{0, 1, 0},
			ExpectedError: true,
		},
		{
			Description: "extension header and data, no payload after",
			Data:        []byte{1, 1, 3, 0, 0, 0, 0, 1},
			ExpectedExtension: Extension{
				BaseLayer: layers.BaseLayer{
					Contents: []byte{1, 1, 3, 0, 0, 0, 0, 1},
					Payload:  []byte{},
				},
				NextHeader: 1, NumLines: 1, Type: 3,
				Data: []byte{0, 0, 0, 0, 1},
			},
		},
		{
			Description: "extension header and data, payload after",
			Data:        []byte{1, 1, 3, 0, 0, 0, 0, 1, 3, 4, 5},
			ExpectedExtension: Extension{
				BaseLayer: layers.BaseLayer{
					Contents: []byte{1, 1, 3, 0, 0, 0, 0, 1},
					Payload:  []byte{3, 4, 5},
				},
				NextHeader: 1, NumLines: 1, Type: 3,
				Data: []byte{0, 0, 0, 0, 1},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Description, func(t *testing.T) {
			var extn Extension
			err := extn.DecodeFromBytes(tc.Data, gopacket.NilDecodeFeedback)
			if tc.ExpectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.ExpectedExtension, extn, "extension must matches")
			}
		})
	}
}

func TestExtensionSerializeTo(t *testing.T) {
	type TestCase struct {
		Description      string
		Extension        Extension
		SerializeOptions gopacket.SerializeOptions

		ExpectedError  bool
		ExpectedBytes  []byte
		ExpectedLength uint8
	}
	testCases := []*TestCase{
		{
			Description:   "empty extension",
			Extension:     Extension{},
			ExpectedBytes: []byte{0, 0, 0},
		},
		{
			Description:      "empty extension with fix lengths",
			Extension:        Extension{},
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			ExpectedBytes:    []byte{0, 1, 0, 0, 0, 0, 0, 0},
			ExpectedLength:   1,
		},
		{
			Description:    "extension with bad length",
			Extension:      Extension{NumLines: 2},
			ExpectedBytes:  []byte{0, 2, 0},
			ExpectedLength: 2,
		},
		{
			Description:   "extension with aligned payload",
			Extension:     Extension{Data: []byte{42, 42, 42, 42, 42}},
			ExpectedBytes: []byte{0, 0, 0, 42, 42, 42, 42, 42},
		},
		{
			Description:      "extension with aligned payload and fix lengths",
			Extension:        Extension{Data: []byte{42, 42, 42, 42, 42}},
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			ExpectedBytes:    []byte{0, 1, 0, 42, 42, 42, 42, 42},
			ExpectedLength:   1,
		},
		{
			Description:   "extension with non-aligned payload",
			Extension:     Extension{Data: []byte{42, 42, 42}},
			ExpectedBytes: []byte{0, 0, 0, 42, 42, 42},
		},
		{
			Description:      "extension with non-aligned payload and fix lengths",
			Extension:        Extension{Data: []byte{42, 42, 42}},
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			ExpectedBytes:    []byte{0, 1, 0, 42, 42, 42, 0, 0},
			ExpectedLength:   1,
		},
		{
			Description: "extension with custom fields",
			Extension: Extension{
				NextHeader: 3,
				NumLines:   4,
				Type:       5,
				Data:       []byte{0, 0, 0, 0, 0},
			},
			ExpectedBytes:  []byte{3, 4, 5, 0, 0, 0, 0, 0},
			ExpectedLength: 4,
		},
		{
			Description: "extension with custom fields and fix lengths",
			Extension: Extension{
				NextHeader: 3,
				NumLines:   4,
				Type:       5,
			},
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			ExpectedBytes:    []byte{3, 1, 5, 0, 0, 0, 0, 0},
			ExpectedLength:   1,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Description, func(t *testing.T) {
			b := gopacket.NewSerializeBuffer()
			err := tc.Extension.SerializeTo(b, tc.SerializeOptions)
			if tc.ExpectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.ExpectedBytes, b.Bytes(), "buffer must match")
				assert.Equal(t, tc.ExpectedLength, tc.Extension.NumLines,
					"updated length field must match")
			}
		})
	}
}
