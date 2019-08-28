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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtnOHPDecodeFromLayer(t *testing.T) {
	type TestCase struct {
		Extension      *Extension
		ErrorAssertion require.ErrorAssertionFunc
	}
	tests := map[string]TestCase{
		"bad payload": {
			Extension: mustCreateExtensionLayer([]byte{0, 2, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0}),
			ErrorAssertion: require.Error,
		},
		"good payload": {
			Extension:      mustCreateExtensionLayer([]byte{0, 1, 0, 0, 0, 0, 0, 0}),
			ErrorAssertion: require.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var extn ExtnOHP
			err := extn.DecodeFromLayer(test.Extension)
			test.ErrorAssertion(t, err)
		})
	}
}

func TestExtnSCMPDecodeFromLayer(t *testing.T) {
	type TestCase struct {
		Extension         *Extension
		ErrorAssertion    require.ErrorAssertionFunc
		ExpectedExtension ExtnSCMP
	}
	tests := map[string]TestCase{
		"good payload, no flags": {
			Extension:         mustCreateExtensionLayer([]byte{0, 1, 0, 0, 0, 0, 0, 0}),
			ExpectedExtension: ExtnSCMP{},
			ErrorAssertion:    require.NoError,
		},
		"good payload, error flag": {
			Extension:         mustCreateExtensionLayer([]byte{0, 1, 0, 0x01, 0, 0, 0, 0}),
			ExpectedExtension: ExtnSCMP{Error: true},
			ErrorAssertion:    require.NoError,
		},
		"good payload, all flags": {
			Extension:         mustCreateExtensionLayer([]byte{0, 1, 0, 0x03, 0, 0, 0, 0}),
			ExpectedExtension: ExtnSCMP{Error: true, HopByHop: true},
			ErrorAssertion:    require.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var extn ExtnSCMP
			err := extn.DecodeFromLayer(test.Extension)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ExpectedExtension, extn, "extension must match")
		})
	}
}

func TestExtnUnkownDecodeFromLayer(t *testing.T) {
	type TestCase struct {
		Extension         *Extension
		ErrorAssertion    require.ErrorAssertionFunc
		ExpectedExtension ExtnUnknown
	}
	// Keep the loop s.t. it's more similar to the rest of the tests in here
	// and it's easier to add new tests
	tests := map[string]TestCase{
		"good payload length": {
			Extension: mustCreateExtensionLayer([]byte{0, 2, 3, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0}),
			ExpectedExtension: ExtnUnknown{Length: 13, TypeField: 3},
			ErrorAssertion:    require.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var extn ExtnUnknown
			err := extn.DecodeFromLayer(test.Extension)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ExpectedExtension, extn, "extension must match")
		})
	}
}

func mustCreateExtensionLayer(b []byte) *Extension {
	var extn Extension
	if err := extn.DecodeFromBytes(b, gopacket.NilDecodeFeedback); err != nil {
		panic(err)
	}
	return &extn
}
