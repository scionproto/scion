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
	trc "github.com/scionproto/scion/go/lib/scrypto/trc/v2"
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
				"Type": "Vote",
				"KeyType": "Online",
				"KeyVersion": 1,
				"AS": "ff00:0:110",
				"crit": ["Type", "AS", "KeyType", "KeyVersion"]
			}`,
			Protected: trc.Protected{
				Algorithm:  scrypto.Ed25519,
				Type:       trc.VoteSignature,
				KeyType:    trc.OnlineKey,
				KeyVersion: 1,
				AS:         a110,
			},
		},
		"Valid offline vote": {
			Input: `
			{
				"alg": "ed25519",
				"Type": "Vote",
				"KeyType": "Offline",
				"KeyVersion": 1,
				"AS": "ff00:0:110",
				"crit": ["Type", "AS", "KeyType", "KeyVersion"]
			}`,
			Protected: trc.Protected{
				Algorithm:  scrypto.Ed25519,
				Type:       trc.VoteSignature,
				KeyType:    trc.OfflineKey,
				KeyVersion: 1,
				AS:         a110,
			},
		},
		"Valid proof of possession": {
			Input: `
			{
				"alg": "ed25519",
				"Type": "ProofOfPossession",
				"KeyType": "Issuing",
				"KeyVersion": 1,
				"AS": "ff00:0:110",
				"crit": ["Type", "AS", "KeyType", "KeyVersion"]
			}`,
			Protected: trc.Protected{
				Algorithm:  scrypto.Ed25519,
				Type:       trc.POPSignature,
				KeyType:    trc.IssuingKey,
				KeyVersion: 1,
				AS:         a110,
			},
		},
		"Algorithm not set": {
			Input: `
			{
				"Type": "ProofOfPossession",
				"KeyType": "Issuing",
				"KeyVersion": 1,
				"AS": "ff00:0:110",
				"crit": ["Type", "AS", "KeyType", "KeyVersion"]
			}`,
			ExpectedErrMsg: trc.ErrAlgorithmNotSet.Error(),
		},
		"Type not set": {
			Input: `
			{
				"alg": "ed25519",
				"KeyType": "Issuing",
				"KeyVersion": 1,
				"AS": "ff00:0:110",
				"crit": ["Type", "AS", "KeyType", "KeyVersion"]
			}`,
			ExpectedErrMsg: trc.ErrSignatureTypeNotSet.Error(),
		},
		"KeyType not set": {
			Input: `
			{
				"alg": "ed25519",
				"Type": "ProofOfPossession",
				"KeyVersion": 1,
				"AS": "ff00:0:110",
				"crit": ["Type", "AS", "KeyType", "KeyVersion"]
			}`,
			ExpectedErrMsg: trc.ErrTypeNotSet.Error(),
		},
		"KeyVersion not set": {
			Input: `
			{
				"alg": "ed25519",
				"Type": "ProofOfPossession",
				"KeyType": "Issuing",
				"AS": "ff00:0:110",
				"crit": ["Type", "AS", "KeyType", "KeyVersion"]
			}`,
			ExpectedErrMsg: trc.ErrKeyVersionNotSet.Error(),
		},
		"AS not set": {
			Input: `
			{
				"alg": "ed25519",
				"Type": "ProofOfPossession",
				"KeyType": "Issuing",
				"KeyVersion": 1,
				"crit": ["Type", "AS", "KeyType", "KeyVersion"]
			}`,
			ExpectedErrMsg: trc.ErrASNotSet.Error(),
		},
		"crit not set": {
			Input: `
			{
				"alg": "ed25519",
				"Type": "ProofOfPossession",
				"KeyType": "Issuing",
				"KeyVersion": 1,
				"AS": "ff00:0:110"
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
				"KeyVersion": 1,
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
			Input:     `"vote"`,
			Assertion: assert.Error,
		},
		"ProofOfPossession": {
			Input:     `"ProofOfPossession"`,
			Assertion: assert.NoError,
			Expected:  trc.POPSignature,
		},
		"Vote": {
			Input:     `"Vote"`,
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
		"Type, KeyType, KeyVersion, AS": {
			Input:     []byte(`{"crit": ["Type", "KeyType", "KeyVersion", "AS"]}`),
			Assertion: assert.NoError,
		},
		"AS, KeyType, KeyVersion, Type": {
			Input:     []byte(`{"crit": ["AS", "KeyType", "KeyVersion", "Type"]}`),
			Assertion: assert.NoError,
		},
		"Duplication length 4": {
			Input:     []byte(`{"crit": ["AS", "AS", "KeyVersion", "Type"]}`),
			Assertion: assert.Error,
		},
		"Duplication length 5": {
			Input:     []byte(`{"crit": ["AS", "AS", "KeyType", "KeyVersion", "Type"]}`),
			Assertion: assert.Error,
		},
		"Missing KeyType": {
			Input:     []byte(`{"crit": ["AS", "Type", "KeyVersion"]}`),
			Assertion: assert.Error,
		},
		"Missing AS": {
			Input:     []byte(`{"crit": ["Type", "KeyType", "KeyVersion"]}`),
			Assertion: assert.Error,
		},
		"Missing Type": {
			Input:     []byte(`{"crit": ["AS", "KeyType", "KeyVersion"]}`),
			Assertion: assert.Error,
		},
		"Missing KeyVersion": {
			Input:     []byte(`{"crit": ["AS", "KeyType", "Type"]}`),
			Assertion: assert.Error,
		},
		"Invalid json": {
			Input:     []byte(`{"crit":10}`),
			Assertion: assert.Error,
		},
		"Unknown Entry": {
			Input:     []byte(`{"crit": ["AS", "KeyType", "Garbage", "Type"]}`),
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
	b, err := json.Marshal(trc.Protected{})
	require.NoError(t, err)
	var protected struct {
		Crit []string `json:"crit"`
	}
	require.NoError(t, json.Unmarshal(b, &protected))
	assert.ElementsMatch(t, []string{"Type", "KeyType", "KeyVersion", "AS"}, protected.Crit)
}
