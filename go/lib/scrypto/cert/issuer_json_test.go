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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
)

type issTest struct {
	baseTest
	ModifyExpected func(*cert.Issuer)
}

func TestIssuerUnmarshalJSON(t *testing.T) {
	tests := map[string]issTest{
		"With revocation key": {
			baseTest: baseTest{
				Modify: func(g *genCert) {
					(*g.Keys)[cert.RevocationKey] = scrypto.KeyMeta{
						KeyVersion: 1,
						Algorithm:  scrypto.Ed25519,
						Key:        []byte{2, 110, 1},
					}
				},
			},
			ModifyExpected: func(c *cert.Issuer) {
				c.Keys[cert.RevocationKey] = scrypto.KeyMeta{
					KeyVersion: 1,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte{2, 110, 1},
				}
			},
		},
		"With optional distribution points": {
			baseTest: baseTest{
				Modify: func(g *genCert) {
					(*g.OptDistPoints) = []addr.IA{ia210}
				},
			},
			ModifyExpected: func(c *cert.Issuer) {
				c.OptionalDistributionPoints = []addr.IA{ia210}
			},
		},
		"Invalid CertificateType": {
			baseTest: baseTest{
				Modify: func(g *genCert) {
					g.CertificateType = "as"
				},
				ExpectedErrMsg: cert.ErrInvalidCertificateType.Error(),
			},
		},
		"Missing issuer.trc_version": {
			baseTest: baseTest{
				Modify: func(g *genCert) {
					delete(*g.Issuer, "trc_version")
				},
				ExpectedErrMsg: cert.ErrIssuerTRCVersionNotSet.Error(),
			},
		},
		"Unknown issuer field": {
			baseTest: baseTest{
				Modify: func(g *genCert) {
					(*g.Issuer)["UNKNOWN"] = true
				},
				ExpectedErrMsg: `json: unknown field "UNKNOWN"`,
			},
		},
	}
	for name, test := range baseUnmarshalJSONTests() {
		if _, ok := tests[name]; ok {
			t.Fatalf("Duplicate test name: %s", name)
		}
		tests[name] = issTest{baseTest: test}
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			expected, g := newGenIssuerCert(time.Now())
			test.Modify(g)
			b, err := json.Marshal(g)
			require.NoError(t, err)
			var iss cert.Issuer
			err = json.Unmarshal(b, &iss)
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
				if test.ModifyExpected != nil {
					test.ModifyExpected(&expected)
				}
				assert.Equal(t, expected, iss)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func TestIssuerTRCUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input          string
		ID             cert.IssuerTRC
		ExpectedErrMsg string
	}{
		"Valid": {
			Input: `
			{
				"trc_version": 4
			}
			`,
			ID: cert.IssuerTRC{TRCVersion: 4},
		},
		"TRCVersion not set": {
			Input:          "{}",
			ExpectedErrMsg: cert.ErrIssuerTRCVersionNotSet.Error(),
		},
		"Unknown field": {
			Input: `
			{
				"trc_version": 4,
				"UNKNOWN": true
			}
			`,
			ExpectedErrMsg: `json: unknown field "UNKNOWN"`,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var id cert.IssuerTRC
			err := json.Unmarshal([]byte(test.Input), &id)
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
				assert.Equal(t, test.ID, id)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func TestTypeIssuerUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input  string
		Assert assert.ErrorAssertionFunc
	}{
		"Valid": {
			Input:  `"issuer"`,
			Assert: assert.NoError,
		},
		"Wrong case": {
			Input:  `"Issuer"`,
			Assert: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var typeIssuer cert.TypeIssuer
			test.Assert(t, json.Unmarshal([]byte(test.Input), &typeIssuer))
		})
	}
}

func TestTypeIssuerMarshalJSON(t *testing.T) {
	var obj struct {
		CertificateType cert.TypeIssuer
	}
	b, err := json.Marshal(obj)
	require.NoError(t, err)
	assert.NoError(t, json.Unmarshal(b, &obj))
}

func TestTypeIssuerMarshalSameASString(t *testing.T) {
	b, err := json.Marshal(cert.TypeIssuer{})
	require.NoError(t, err)
	assert.Equal(t, cert.TypeIssuerJSON, strings.Trim(string(b), `"`))
}

func newGenIssuerCert(now time.Time) (cert.Issuer, *genCert) {
	c := newIssuerCert(now)
	g := &genCert{
		Subject:         &c.Subject,
		Version:         &c.Version,
		FormatVersion:   &c.FormatVersion,
		Description:     &c.Description,
		OptDistPoints:   &c.OptionalDistributionPoints,
		Validity:        c.Validity,
		Keys:            &c.Keys,
		CertificateType: cert.TypeIssuerJSON,
	}
	g.Issuer = &map[string]interface{}{
		"trc_version": c.Issuer.TRCVersion,
	}
	return c, g
}

func newIssuerCert(now time.Time) cert.Issuer {
	c := cert.Issuer{
		Base: newBaseCert(now),
		Issuer: cert.IssuerTRC{
			TRCVersion: 4,
		},
	}
	c.Keys = map[cert.KeyType]scrypto.KeyMeta{
		cert.IssuingKey: {
			KeyVersion: 1,
			Algorithm:  scrypto.Ed25519,
			Key:        []byte{3, 110, 1},
		},
	}
	c.Version = 2
	return c
}
