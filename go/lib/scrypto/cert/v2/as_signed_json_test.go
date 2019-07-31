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
	"github.com/scionproto/scion/go/lib/scrypto/cert/v2"
)

func TestProtectedUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input          string
		Protected      cert.ProtectedAS
		ExpectedErrMsg string
	}{
		"Valid": {
			Input: `
			{
				"alg": "ed25519",
				"Type": "Certificate",
				"CertificateVersion": 2,
				"IA": "1-ff00:0:110",
				"crit": ["Type", "CertificateVersion", "IA"]
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
				"Type": "Certificate",
				"CertificateVersion": 2,
				"IA": "1-ff00:0:110",
				"crit": ["Type", "CertificateVersion", "IA"]
			}`,
			ExpectedErrMsg: cert.ErrAlgorithmNotSet.Error(),
		},
		"Type not set": {
			Input: `
			{
				"alg": "ed25519",
				"CertificateVersion": 2,
				"IA": "1-ff00:0:110",
				"crit": ["Type", "CertificateVersion", "IA"]
			}`,
			ExpectedErrMsg: cert.ErrSignatureTypeNotSet.Error(),
		},
		"CertificateVersion not set": {
			Input: `
			{
				"alg": "ed25519",
				"Type": "Certificate",
				"IA": "1-ff00:0:110",
				"crit": ["Type", "CertificateVersion", "IA"]
			}`,
			ExpectedErrMsg: cert.ErrIssuerCertificateVersionNotSet.Error(),
		},
		"IA not set": {
			Input: `
			{
				"alg": "ed25519",
				"Type": "Certificate",
				"CertificateVersion": 2,
				"crit": ["Type", "CertificateVersion", "IA"]
			}`,
			ExpectedErrMsg: cert.ErrIANotSet.Error(),
		},
		"crit not set": {
			Input: `
			{
				"alg": "ed25519",
				"Type": "Certificate",
				"CertificateVersion": 2,
				"IA": "1-ff00:0:110"
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
				"KeyVersion": 1,
				"Algorithm": "ed25519"
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
			Input:     []byte(`"Certificate"`),
			Assertion: assert.NoError,
		},
		"Wrong case": {
			Input:     []byte(`"certificate"`),
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
		Expected  time.Duration
		Assertion assert.ErrorAssertionFunc
	}{
		"Valid": {
			Input:     []byte(`{"crit": ["Type", "CertificateVersion", "IA"]}`),
			Assertion: assert.NoError,
		},
		"Out of order": {
			Input:     []byte(`{"crit": ["Type", "IA", "CertificateVersion"]}`),
			Assertion: assert.Error,
		},
		"Length mismatch": {
			Input:     []byte(`{"crit": ["Type", "CertificateVersion"]}`),
			Assertion: assert.Error,
		},
		"Invalid json": {
			Input:     []byte(`{"crit":10}`),
			Assertion: assert.Error,
		},
		"Unknown Entry": {
			Input:     []byte(`{"crit": ["Type", "CertificateVersion", "Garbage", "IA"]}`),
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

func TestCritMarshalJSON(t *testing.T) {
	mockProtected := struct {
		Crit cert.CritAS `json:"crit"`
	}{}
	b, err := json.Marshal(mockProtected)
	require.NoError(t, err)
	var protected struct {
		Crit []string `json:"crit"`
	}
	require.NoError(t, json.Unmarshal(b, &protected))
	assert.ElementsMatch(t, []string{"Type", "CertificateVersion", "IA"}, protected.Crit)
}
