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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert/v2"
)

func TestIssuerValidate(t *testing.T) {
	tests := map[string]struct {
		Modify         func(*cert.Issuer)
		ExpectedErrMsg string
	}{
		"Valid": {
			Modify: func(_ *cert.Issuer) {},
		},
		"Revocation Key": {
			Modify: func(c *cert.Issuer) {
				c.Keys[cert.RevocationKey] = scrypto.KeyMeta{
					KeyVersion: 1,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte{3, 110, 1},
				}
			},
		},
		"Base Validation error": {
			Modify: func(c *cert.Issuer) {
				c.Subject.A = 0
			},
			ExpectedErrMsg: cert.InvalidSubject,
		},
		"No Issuing Key": {
			Modify: func(c *cert.Issuer) {
				delete(c.Keys, cert.IssuingKey)
			},
			ExpectedErrMsg: cert.MissingKey,
		},
		"SigningKey": {
			Modify: func(c *cert.Issuer) {
				c.Keys[cert.SigningKey] = scrypto.KeyMeta{
					KeyVersion: 1,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte{2, 110, 1},
				}
			},
			ExpectedErrMsg: cert.UnexpectedKey,
		},
		"EncryptionKey": {
			Modify: func(c *cert.Issuer) {
				c.Keys[cert.EncryptionKey] = scrypto.KeyMeta{
					KeyVersion: 1,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte{1, 110, 1},
				}
			},
			ExpectedErrMsg: cert.UnexpectedKey,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c := newIssuerCert()
			test.Modify(&c)
			err := c.Validate()
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}
