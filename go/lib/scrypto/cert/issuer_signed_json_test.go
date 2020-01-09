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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
)

func TestProtectedIssuerUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input          string
		Protected      cert.ProtectedIssuer
		ExpectedErrMsg string
	}{
		"Valid": {
			Input: `
			{
				"alg": "ed25519",
				"type": "trc",
				"trc_version": 4,
				"crit": ["type", "trc_version"]
			}`,
			Protected: cert.ProtectedIssuer{
				Algorithm:  scrypto.Ed25519,
				TRCVersion: 4,
			},
		},
		"Algorithm not set": {
			Input: `
			{
				"type": "trc",
				"trc_version": 4,
				"crit": ["type", "trc_version"]
			}`,
			ExpectedErrMsg: cert.ErrAlgorithmNotSet.Error(),
		},
		"Type not set": {
			Input: `
			{
				"alg": "ed25519",
				"trc_version": 4,
				"crit": ["type", "trc_version"]
			}`,
			ExpectedErrMsg: cert.ErrSignatureTypeNotSet.Error(),
		},
		"TRCVersion not set": {
			Input: `
			{
				"alg": "ed25519",
				"type": "trc",
				"crit": ["type", "trc_version"]
			}`,
			ExpectedErrMsg: cert.ErrTRCVersionNotSet.Error(),
		},
		"crit not set": {
			Input: `
			{
				"alg": "ed25519",
				"type": "trc",
				"trc_version": 4
			}`,
			ExpectedErrMsg: cert.ErrCritNotSet.Error(),
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
				"algorithm": "ed25519"
			`,
			ExpectedErrMsg: "unexpected end of JSON input",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var protected cert.ProtectedIssuer
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

func TestSignatureTypeTRCUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input     []byte
		Expected  time.Duration
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Input:     []byte(`"trc"`),
			Assertion: assert.NoError,
		},
		"Wrong case": {
			Input:     []byte(`"TRC"`),
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var sigType cert.SignatureTypeTRC
			test.Assertion(t, json.Unmarshal(test.Input, &sigType))
		})
	}
}

func TestSignatureTypeTRCMarshalJSON(t *testing.T) {
	mockProtected := struct {
		Type cert.SignatureTypeTRC
	}{}
	b, err := json.Marshal(mockProtected)
	require.NoError(t, err)
	var protected struct {
		Type string
	}
	require.NoError(t, json.Unmarshal(b, &protected))
	assert.Equal(t, cert.SignatureTypeTRCJSON, protected.Type)
}

func TestCritIssuerUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input     []byte
		Expected  time.Duration
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Input:     []byte(`{"crit": ["type", "trc_version"]}`),
			Assertion: assert.NoError,
		},
		"Out of order": {
			Input:     []byte(`{"crit": ["trc_version", "type"]}`),
			Assertion: assert.Error,
		},
		"Length mismatch": {
			Input:     []byte(`{"crit": ["type"]}`),
			Assertion: assert.Error,
		},
		"Invalid json": {
			Input:     []byte(`{"crit":10}`),
			Assertion: assert.Error,
		},
		"Unknown Entry": {
			Input:     []byte(`{"crit": ["type", "Garbage"]}`),
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var meta struct{ Crit cert.CritIssuer }
			test.Assertion(t, json.Unmarshal(test.Input, &meta))
		})
	}
}

func TestCritIssuerMarshalJSON(t *testing.T) {
	mockProtected := struct {
		Crit cert.CritIssuer `json:"crit"`
	}{}
	b, err := json.Marshal(mockProtected)
	require.NoError(t, err)
	var protected struct {
		Crit []string `json:"crit"`
	}
	require.NoError(t, json.Unmarshal(b, &protected))
	assert.ElementsMatch(t, []string{"type", "trc_version"}, protected.Crit)
}
