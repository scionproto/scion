// Copyright 2019 Anapaya Systems
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

package renewal_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert/renewal"
)

func TestParseSignedRequest(t *testing.T) {
	tests := map[string]struct {
		Input          string
		SignedRequest  renewal.SignedRequest
		ExpectedErrMsg string
	}{
		"Valid": {
			Input: `
			{
				"payload": "testrequest",
				"protected": "protected",
				"signature": "c2lnbmF0dXJl"
			}
			`,
			SignedRequest: renewal.SignedRequest{
				Encoded:          "testrequest",
				EncodedProtected: "protected",
				Signature:        []byte("signature"),
			},
		},
		"Invalid JSON": {
			Input: `
			{
				"payload": "testrequest",
				"protected": "protected",
				"signature": "not base64"
			}
			`,
			ExpectedErrMsg: "illegal base64 data at input byte 3",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			sr, err := renewal.ParseSignedRequest([]byte(test.Input))
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
				assert.Equal(t, test.SignedRequest, sr)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func TestProtectedUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input          string
		Protected      renewal.Protected
		ExpectedErrMsg string
	}{
		"Valid": {
			Input: `
			{
				"alg": "ed25519",
				"key_type": "signing",
				"key_version": 2,
				"crit": ["key_type", "key_version"]
			}`,
			Protected: renewal.Protected{
				Algorithm:  scrypto.Ed25519,
				KeyType:    renewal.SigningKey,
				KeyVersion: 2,
			},
		},
		"Algorithm not set": {
			Input: `
			{
				"key_type": "signing",
				"key_version": 2,
				"crit": ["key_type", "key_version"]
			}`,
			ExpectedErrMsg: renewal.ErrMissingProtectedField.Error(),
		},
		"Key type not set": {
			Input: `
			{
				"alg": "ed25519",
				"key_version": 2,
				"crit": ["key_type", "key_version"]
			}`,
			ExpectedErrMsg: renewal.ErrMissingProtectedField.Error(),
		},
		"Key version not set": {
			Input: `
			{
				"alg": "ed25519",
				"key_type": "signing",
				"crit": ["key_type", "key_version"]
			}`,
			ExpectedErrMsg: renewal.ErrMissingProtectedField.Error(),
		},
		"crit not set": {
			Input: `
			{
				"alg": "ed25519",
				"key_type": "signing",
				"key_version": 2
			}`,
			ExpectedErrMsg: renewal.ErrMissingProtectedField.Error(),
		},
		"unknown field": {
			Input: `
			{
				"alg": "ed25519",
				"key_type": "signing",
				"version": 2,
				"crit": ["key_type", "key_version"]
			}`,
			ExpectedErrMsg: `json: unknown field "version"`,
		},
		"invalid JSON": {
			Input: `
			{
				"alg": "ed25519",
				"key_type": "signing",
			`,
			ExpectedErrMsg: "unexpected end of JSON input",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var protected renewal.Protected
			err := json.Unmarshal([]byte(test.Input), &protected)
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
				assert.Equal(t, test.Protected, protected)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}
