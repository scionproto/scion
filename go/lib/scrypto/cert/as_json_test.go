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

type asTest struct {
	baseTest
	ModifyExpected func(*cert.AS)
}

func TestASUnmarshalJSON(t *testing.T) {
	tests := map[string]asTest{
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
			ModifyExpected: func(c *cert.AS) {
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
			ModifyExpected: func(c *cert.AS) {
				c.OptionalDistributionPoints = []addr.IA{ia210}
			},
		},
		"Invalid CertificateType": {
			baseTest: baseTest{
				Modify: func(g *genCert) {
					g.CertificateType = "issuer"
				},
				ExpectedErrMsg: cert.ErrInvalidCertificateType.Error(),
			},
		},
		"Missing issuer.isd_as": {
			baseTest: baseTest{
				Modify: func(g *genCert) {
					delete(*g.Issuer, "isd_as")
				},
				ExpectedErrMsg: cert.ErrIssuerIANotSet.Error(),
			},
		},
		"Missing issuer.certificate_version": {
			baseTest: baseTest{
				Modify: func(g *genCert) {
					delete(*g.Issuer, "certificate_version")
				},
				ExpectedErrMsg: cert.ErrIssuerCertificateVersionNotSet.Error(),
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
		tests[name] = asTest{baseTest: test}
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			expected, g := newGenASCert(time.Now())
			test.Modify(g)
			b, err := json.Marshal(g)
			require.NoError(t, err)
			var as cert.AS
			err = json.Unmarshal(b, &as)
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
				if test.ModifyExpected != nil {
					test.ModifyExpected(&expected)
				}
				assert.Equal(t, expected, as)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

func TestIssuerCertIDUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input          string
		ID             cert.IssuerCertID
		ExpectedErrMsg string
	}{
		"Valid": {
			Input: `
			{
				"isd_as": "1-ff00:0:110",
				"certificate_version": 2
			}
			`,
			ID: cert.IssuerCertID{
				IA:                 ia110,
				CertificateVersion: 2,
			},
		},
		"IA not set": {
			Input: `
			{
				"certificate_version": 2
			}
			`,
			ExpectedErrMsg: cert.ErrIssuerIANotSet.Error(),
		},
		"CertificateVersion not set": {
			Input: `
			{
				"isd_as": "1-ff00:0:110"
			}
			`,
			ExpectedErrMsg: cert.ErrIssuerCertificateVersionNotSet.Error(),
		},
		"Unknown field": {
			Input: `
			{
				"isd_as": "1-ff00:0:110",
				"certificate_version": 2,
				"UNKNOWN": true
			}
			`,
			ExpectedErrMsg: `json: unknown field "UNKNOWN"`,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var id cert.IssuerCertID
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

func TestTypeASUnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		Input  string
		Assert assert.ErrorAssertionFunc
	}{
		"Valid": {
			Input:  `"as"`,
			Assert: assert.NoError,
		},
		"Wrong case": {
			Input:  `"AS"`,
			Assert: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var typeAS cert.TypeAS
			test.Assert(t, json.Unmarshal([]byte(test.Input), &typeAS))
		})
	}
}

func TestTypeASMarshalJSON(t *testing.T) {
	var obj struct {
		CertificateType cert.TypeAS
	}
	b, err := json.Marshal(obj)
	require.NoError(t, err)
	assert.NoError(t, json.Unmarshal(b, &obj))
}

func TestTypeASMarshalSameASString(t *testing.T) {
	b, err := json.Marshal(cert.TypeAS{})
	require.NoError(t, err)
	assert.Equal(t, cert.TypeASJSON, strings.Trim(string(b), `"`))
}

func newGenASCert(now time.Time) (cert.AS, *genCert) {
	c := newASCert(now)
	g := &genCert{
		Subject:         &c.Subject,
		Version:         &c.Version,
		FormatVersion:   &c.FormatVersion,
		Description:     &c.Description,
		OptDistPoints:   &c.OptionalDistributionPoints,
		Validity:        c.Validity,
		Keys:            &c.Keys,
		CertificateType: cert.TypeASJSON,
	}
	g.Issuer = &map[string]interface{}{
		"isd_as":              c.Issuer.IA,
		"certificate_version": c.Issuer.CertificateVersion,
	}
	return c, g
}

func newASCert(now time.Time) cert.AS {
	c := cert.AS{
		Base: newBaseCert(now),
		Issuer: cert.IssuerCertID{
			IA:                 ia110,
			CertificateVersion: 2,
		},
	}
	c.Keys = map[cert.KeyType]scrypto.KeyMeta{
		cert.SigningKey: {
			KeyVersion: 1,
			Algorithm:  scrypto.Ed25519,
			Key:        []byte{0, 110, 1},
		},
		cert.EncryptionKey: {
			KeyVersion: 1,
			Algorithm:  scrypto.Ed25519,
			Key:        []byte{1, 110, 1},
		},
	}
	c.Version = 4
	return c
}
