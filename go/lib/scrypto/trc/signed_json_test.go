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

package trc_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
)

func TestProtectedUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input          string
		Protected      trc.Protected
		ExpectedErrMsg string
	}{
		"Valid online vote": {
			Input: `
			{
				"alg": "ed25519",
				"type": "vote",
				"key_type": "voting_online",
				"key_version": 1,
				"as": "ff00:0:110",
				"crit": ["type", "key_type", "key_version", "as"]
			}`,
			Protected: trc.Protected{
				Algorithm:  scrypto.Ed25519,
				Type:       trc.VoteSignature,
				KeyType:    trc.VotingOnlineKey,
				KeyVersion: 1,
				AS:         a110,
			},
		},
		"Valid offline vote": {
			Input: `
			{
				"alg": "ed25519",
				"type": "vote",
				"key_type": "voting_offline",
				"key_version": 1,
				"as": "ff00:0:110",
				"crit": ["type", "key_type", "key_version", "as"]
			}`,
			Protected: trc.Protected{
				Algorithm:  scrypto.Ed25519,
				Type:       trc.VoteSignature,
				KeyType:    trc.VotingOfflineKey,
				KeyVersion: 1,
				AS:         a110,
			},
		},
		"Valid proof_of_possession": {
			Input: `
			{
				"alg": "ed25519",
				"type": "proof_of_possession",
				"key_type": "issuing_grant",
				"key_version": 1,
				"as": "ff00:0:110",
				"crit": ["type", "key_type", "key_version", "as"]
			}`,
			Protected: trc.Protected{
				Algorithm:  scrypto.Ed25519,
				Type:       trc.POPSignature,
				KeyType:    trc.IssuingGrantKey,
				KeyVersion: 1,
				AS:         a110,
			},
		},
		"algorithm not set": {
			Input: `
			{
				"type": "proof_of_possession",
				"key_type": "issuing_grant",
				"key_version": 1,
				"as": "ff00:0:110",
				"crit": ["type", "key_type", "key_version", "as"]
			}`,
			ExpectedErrMsg: trc.ErrAlgorithmNotSet.Error(),
		},
		"type not set": {
			Input: `
			{
				"alg": "ed25519",
				"key_type": "issuing_grant",
				"key_version": 1,
				"as": "ff00:0:110",
				"crit": ["type", "key_type", "key_version", "as"]
			}`,
			ExpectedErrMsg: trc.ErrSignatureTypeNotSet.Error(),
		},
		"key_type not set": {
			Input: `
			{
				"alg": "ed25519",
				"type": "proof_of_possession",
				"key_version": 1,
				"as": "ff00:0:110",
				"crit": ["type", "key_type", "key_version", "as"]
			}`,
			ExpectedErrMsg: trc.ErrKeyTypeNotSet.Error(),
		},
		"key_version not set": {
			Input: `
			{
				"alg": "ed25519",
				"type": "proof_of_possession",
				"key_type": "issuing_grant",
				"as": "ff00:0:110",
				"crit": ["type", "key_type", "key_version", "as"]
			}`,
			ExpectedErrMsg: trc.ErrKeyVersionNotSet.Error(),
		},
		"as not set": {
			Input: `
			{
				"alg": "ed25519",
				"type": "proof_of_possession",
				"key_type": "issuing_grant",
				"key_version": 1,
				"crit": ["type", "key_type", "key_version", "as"]
			}`,
			ExpectedErrMsg: trc.ErrASNotSet.Error(),
		},
		"crit not set": {
			Input: `
			{
				"alg": "ed25519",
				"type": "proof_of_possession",
				"key_type": "issuing_grant",
				"key_version": 1,
				"as": "ff00:0:110"
			}`,
			ExpectedErrMsg: trc.ErrCritNotSet.Error(),
		},
		"Unknown field": {
			Input: `
			{
				"UnknownField": "UNKNOWN"
			}`,
			ExpectedErrMsg: `json: unknown field "UnknownField"`,
		},
		"invalid json": {
			Input: `
			{
				"key_version": 1,
				"Algorithm": "ed25519"
			`,
			ExpectedErrMsg: "unexpected end of JSON input",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var protected trc.Protected
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

func TestSignatureTypeUnmarshalJson(t *testing.T) {
	tests := map[string]struct {
		Input     string
		Assertion assert.ErrorAssertionFunc
		Expected  trc.SignatureType
	}{
		"Garbage": {
			Input:     `"test"`,
			Assertion: assert.Error,
		},
		"Integer": {
			Input:     `42`,
			Assertion: assert.Error,
		},
		"Wrong case": {
			Input:     `"Vote"`,
			Assertion: assert.Error,
		},
		"proof_of_possession": {
			Input:     `"proof_of_possession"`,
			Assertion: assert.NoError,
			Expected:  trc.POPSignature,
		},
		"vote": {
			Input:     `"vote"`,
			Assertion: assert.NoError,
			Expected:  trc.VoteSignature,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var attr trc.SignatureType
			test.Assertion(t, json.Unmarshal([]byte(test.Input), &attr))
			assert.Equal(t, test.Expected, attr)
		})
	}
}

func TestCritUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input     []byte
		Expected  time.Duration
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Input:     []byte(`{"crit": ["type", "key_type", "key_version", "as"]}`),
			Assertion: assert.NoError,
		},
		"Out of order": {
			Input:     []byte(`{"crit": ["as", "type", "key_type", "key_version"]}`),
			Assertion: assert.Error,
		},
		"Length mismatch": {
			Input:     []byte(`{"crit": ["as", "key_type", "type"]}`),
			Assertion: assert.Error,
		},
		"Invalid json": {
			Input:     []byte(`{"crit":10}`),
			Assertion: assert.Error,
		},
		"Unknown Entry": {
			Input:     []byte(`{"crit": ["as", "key_type", "Garbage", "type"]}`),
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var meta struct{ Crit trc.Crit }
			test.Assertion(t, json.Unmarshal(test.Input, &meta))
		})
	}
}

func TestCritMarshalJSON(t *testing.T) {
	mockProtected := struct {
		Crit trc.Crit `json:"crit"`
	}{}
	b, err := json.Marshal(mockProtected)
	require.NoError(t, err)
	var protected struct {
		Crit []string `json:"crit"`
	}
	require.NoError(t, json.Unmarshal(b, &protected))
	assert.ElementsMatch(t, []string{"type", "key_type", "key_version", "as"}, protected.Crit)
}
