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

package cert_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto/cert"
)

func TestChainUnmarshalJSON(t *testing.T) {
	as := cert.SignedAS{
		Encoded:          cert.EncodedAS("encoded AS certificate"),
		EncodedProtected: cert.EncodedProtectedAS("encoded AS protected"),
		Signature:        []byte("AS signature"),
	}
	issuer := cert.SignedIssuer{
		Encoded:          cert.EncodedIssuer("encoded issuer certificate"),
		EncodedProtected: cert.EncodedProtectedIssuer("encoded issuer protected"),
		Signature:        []byte("issuer signature"),
	}
	chainRaw, err := json.Marshal(&[]interface{}{issuer, as})
	require.NoError(t, err)

	var chain cert.Chain
	err = json.Unmarshal(chainRaw, &chain)
	require.NoError(t, err)
	assert.Equal(t, as, chain.AS)
	assert.Equal(t, issuer, chain.Issuer)
}

func TestChainUnmarshalJSONError(t *testing.T) {
	tests := map[string]struct {
		Input          string
		ExpectedErrMsg string
	}{
		"invalid signed AS": {
			Input: `
			[
				{
					"payload": "ZW5jb2RlZCBBUyBjZXJ0aWZpY2F0ZQ==",
					"protected": 1
				},
				{
					"payload": "ZW5jb2RlZCBJc3N1ZXIgQ2VydGlmaWNhdGU=",
					"protected": "ZW5jb2RlZCBJc3N1ZXIgUHJvdGVjdGVk",
					"signature": "c2lnbmF0dXJl"
				}
			]
			`,
			ExpectedErrMsg: "json: cannot unmarshal number into Go struct field",
		},
		"too short": {
			Input: `
			[
				{
					"payload": "ZW5jb2RlZCBBUyBjZXJ0aWZpY2F0ZQ==",
					"protected": "ZW5jb2RlZCBBUyBwcm90ZWN0ZWQ=",
					"signature": "c2lnbmF0dXJl"
				}
			]
			`,
			ExpectedErrMsg: cert.ErrInvalidChainLength.Error(),
		},
		"too long": {
			Input: `
			[
				{
					"payload": "ZW5jb2RlZCBBUyBjZXJ0aWZpY2F0ZQ==",
					"protected": "ZW5jb2RlZCBBUyBwcm90ZWN0ZWQ=",
					"signature": "c2lnbmF0dXJl"
				},
				{
					"payload": "ZW5jb2RlZCBJc3N1ZXIgQ2VydGlmaWNhdGU=",
					"protected": "ZW5jb2RlZCBJc3N1ZXIgUHJvdGVjdGVk",
					"signature": "c2lnbmF0dXJl"
				},
				{
					"payload": "ZW5jb2RlZCBJc3N1ZXIgQ2VydGlmaWNhdGU=",
					"protected": "ZW5jb2RlZCBJc3N1ZXIgUHJvdGVjdGVk",
					"signature": "c2lnbmF0dXJl"
				}
			]
			`,
			ExpectedErrMsg: cert.ErrInvalidChainLength.Error(),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var chain cert.Chain
			err := json.Unmarshal([]byte(test.Input), &chain)
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.ExpectedErrMsg)
		})
	}
}

func TestChainMarshalJSON(t *testing.T) {
	chain := cert.Chain{
		Issuer: cert.SignedIssuer{
			Encoded:          cert.EncodedIssuer("encoded issuer certificate"),
			EncodedProtected: cert.EncodedProtectedIssuer("encoded issuer protected"),
			Signature:        []byte("issuer signature"),
		},
		AS: cert.SignedAS{
			Encoded:          cert.EncodedAS("encoded AS certificate"),
			EncodedProtected: cert.EncodedProtectedAS("encoded AS protected"),
			Signature:        []byte("AS signature"),
		},
	}
	chainRaw, err := json.Marshal(chain)
	require.NoError(t, err)

	var as cert.SignedAS
	var issuer cert.SignedIssuer
	err = json.Unmarshal(chainRaw, &[]interface{}{&issuer, &as})
	require.NoError(t, err)
	assert.Equal(t, chain.AS, as)
	assert.Equal(t, chain.Issuer, issuer)
}
