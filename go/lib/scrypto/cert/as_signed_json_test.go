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

func TestProtectedASUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input          string
		Protected      cert.ProtectedAS
		ExpectedErrMsg string
	}{
		"Valid": {
			Input: `
			{
				"alg": "ed25519",
				"type": "certificate",
				"certificate_version": 2,
				"isd_as": "1-ff00:0:110",
				"crit": ["type", "certificate_version", "isd_as"]
			}`,
			Protected: cert.ProtectedAS{
				Algorithm:          scrypto.Ed25519,
				CertificateVersion: 2,
				IA:                 ia110,
			},
		},
		"Algorithm not set": {
			Input: `
			{
				"type": "certificate",
				"certificate_version": 2,
				"isd_as": "1-ff00:0:110",
				"crit": ["type", "certificate_version", "isd_as"]
			}`,
			ExpectedErrMsg: cert.ErrAlgorithmNotSet.Error(),
		},
		"Type not set": {
			Input: `
			{
				"alg": "ed25519",
				"certificate_version": 2,
				"isd_as": "1-ff00:0:110",
				"crit": ["type", "certificate_version", "isd_as"]
			}`,
			ExpectedErrMsg: cert.ErrSignatureTypeNotSet.Error(),
		},
		"CertificateVersion not set": {
			Input: `
			{
				"alg": "ed25519",
				"type": "certificate",
				"isd_as": "1-ff00:0:110",
				"crit": ["type", "certificate_version", "isd_as"]
			}`,
			ExpectedErrMsg: cert.ErrIssuerCertificateVersionNotSet.Error(),
		},
		"IA not set": {
			Input: `
			{
				"alg": "ed25519",
				"type": "certificate",
				"certificate_version": 2,
				"crit": ["type", "certificate_version", "isd_as"]
			}`,
			ExpectedErrMsg: cert.ErrIANotSet.Error(),
		},
		"crit not set": {
			Input: `
			{
				"alg": "ed25519",
				"type": "certificate",
				"certificate_version": 2,
				"isd_as": "1-ff00:0:110"
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
			var protected cert.ProtectedAS
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

func TestSignatureTypeCertificateUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input     []byte
		Expected  time.Duration
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Input:     []byte(`"certificate"`),
			Assertion: assert.NoError,
		},
		"Wrong case": {
			Input:     []byte(`"Certificate"`),
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var sigType cert.SignatureTypeCertificate
			test.Assertion(t, json.Unmarshal(test.Input, &sigType))
		})
	}
}

func TestSignatureTypeCertificateMarshalJSON(t *testing.T) {
	mockProtected := struct {
		Type cert.SignatureTypeCertificate
	}{}
	b, err := json.Marshal(mockProtected)
	require.NoError(t, err)
	var protected struct {
		Type string
	}
	require.NoError(t, json.Unmarshal(b, &protected))
	assert.Equal(t, cert.SignatureTypeCertificateJSON, protected.Type)
}

func TestCritASUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input     []byte
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Input:     []byte(`{"crit": ["type", "certificate_version", "isd_as"]}`),
			Assertion: assert.NoError,
		},
		"Out of order": {
			Input:     []byte(`{"crit": ["type", "isd_as", "certificate_version"]}`),
			Assertion: assert.Error,
		},
		"Length mismatch": {
			Input:     []byte(`{"crit": ["type", "certificate_version"]}`),
			Assertion: assert.Error,
		},
		"Invalid json": {
			Input:     []byte(`{"crit":10}`),
			Assertion: assert.Error,
		},
		"Unknown Entry": {
			Input:     []byte(`{"crit": ["type", "certificate_version", "Garbage", "isd_as"]}`),
			Assertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var meta struct{ Crit cert.CritAS }
			test.Assertion(t, json.Unmarshal(test.Input, &meta))
		})
	}
}

func TestCritASMarshalJSON(t *testing.T) {
	mockProtected := struct {
		Crit cert.CritAS `json:"crit"`
	}{}
	b, err := json.Marshal(mockProtected)
	require.NoError(t, err)
	var protected struct {
		Crit []string `json:"crit"`
	}
	require.NoError(t, json.Unmarshal(b, &protected))
	assert.ElementsMatch(t, []string{"type", "certificate_version", "isd_as"}, protected.Crit)
}
