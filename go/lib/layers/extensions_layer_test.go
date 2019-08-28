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
		Data              []byte
		ErrorAssertion    require.ErrorAssertionFunc
		ExpectedExtension Extension
	}
	tests := map[string]TestCase{
		"nil input:": {
			ErrorAssertion: require.Error,
		},
		"truncated header": {
			Data:           []byte{1},
			ErrorAssertion: require.Error,
		},
		"truncated extension body": {
			Data:           []byte{0, 1, 0},
			ErrorAssertion: require.Error,
		},
		"invalid extension header all zero": {
			Data:              []byte{0, 0, 0},
			ErrorAssertion:    require.Error,
			ExpectedExtension: Extension{},
		},
		"invalid extension header mismatch expected actual size": {
			Data:              []byte{1, 255, 1, 1, 1, 1, 1, 1, 1},
			ErrorAssertion:    require.Error,
			ExpectedExtension: Extension{},
		},
		"invalid extension header smaller than min": {
			Data:              []byte{1, 255},
			ErrorAssertion:    require.Error,
			ExpectedExtension: Extension{},
		},
		"extension header and data, no payload after": {
			Data:           []byte{1, 1, 3, 0, 0, 0, 0, 1},
			ErrorAssertion: require.NoError,
			ExpectedExtension: Extension{
				BaseLayer: layers.BaseLayer{
					Contents: []byte{1, 1, 3, 0, 0, 0, 0, 1},
					Payload:  []byte{},
				},
				NextHeader: 1, NumLines: 1, Type: 3,
				Data: []byte{0, 0, 0, 0, 1},
			},
		},
		"extension header and data, payload after": {
			Data:           []byte{1, 1, 3, 0, 0, 0, 0, 1, 3, 4, 5},
			ErrorAssertion: require.NoError,
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
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var extn Extension
			err := extn.DecodeFromBytes(test.Data, gopacket.NilDecodeFeedback)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ExpectedExtension, extn, "extension must match")
		})
	}
}

func TestExtensionSerializeTo(t *testing.T) {
	type TestCase struct {
		Extension        Extension
		SerializeOptions gopacket.SerializeOptions

		ErrorAssertion require.ErrorAssertionFunc
		ExpectedBytes  []byte
		ExpectedLength uint8
	}
	tests := map[string]TestCase{
		"empty extension": {
			Extension:      Extension{},
			ExpectedBytes:  []byte{0, 0, 0},
			ErrorAssertion: require.NoError,
		},
		"empty extension with fix lengths": {
			Extension:        Extension{},
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			ExpectedBytes:    []byte{0, 1, 0, 0, 0, 0, 0, 0},
			ExpectedLength:   1,
			ErrorAssertion:   require.NoError,
		},
		"extension with bad length": {
			Extension:      Extension{NumLines: 2},
			ExpectedBytes:  []byte{0, 2, 0},
			ExpectedLength: 2,
			ErrorAssertion: require.NoError,
		},
		"extension with aligned payload": {
			Extension:      Extension{Data: []byte{42, 42, 42, 42, 42}},
			ExpectedBytes:  []byte{0, 0, 0, 42, 42, 42, 42, 42},
			ErrorAssertion: require.NoError,
		},
		"extension with aligned payload and fix lengths": {
			Extension:        Extension{Data: []byte{42, 42, 42, 42, 42}},
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			ExpectedBytes:    []byte{0, 1, 0, 42, 42, 42, 42, 42},
			ExpectedLength:   1,
			ErrorAssertion:   require.NoError,
		},
		"extension with non-aligned payload": {
			Extension:      Extension{Data: []byte{42, 42, 42}},
			ExpectedBytes:  []byte{0, 0, 0, 42, 42, 42},
			ErrorAssertion: require.NoError,
		},
		"extension with non-aligned payload and fix lengths": {
			Extension:        Extension{Data: []byte{42, 42, 42}},
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			ExpectedBytes:    []byte{0, 1, 0, 42, 42, 42, 0, 0},
			ExpectedLength:   1,
			ErrorAssertion:   require.NoError,
		},
		"extension with custom fields": {
			Extension: Extension{
				NextHeader: 3,
				NumLines:   4,
				Type:       5,
				Data:       []byte{0, 0, 0, 0, 0},
			},
			ExpectedBytes:  []byte{3, 4, 5, 0, 0, 0, 0, 0},
			ExpectedLength: 4,
			ErrorAssertion: require.NoError,
		},
		"extension with custom fields and fix lengths": {
			Extension: Extension{
				NextHeader: 3,
				NumLines:   4,
				Type:       5,
			},
			SerializeOptions: gopacket.SerializeOptions{FixLengths: true},
			ExpectedBytes:    []byte{3, 1, 5, 0, 0, 0, 0, 0},
			ExpectedLength:   1,
			ErrorAssertion:   require.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			b := gopacket.NewSerializeBuffer()
			err := test.Extension.SerializeTo(b, test.SerializeOptions)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ExpectedBytes, b.Bytes(), "buffer must match")
			assert.Equal(t, test.ExpectedLength, test.Extension.NumLines,
				"updated length field must match")
		})
	}
}
