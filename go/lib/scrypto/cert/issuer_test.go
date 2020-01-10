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
	"time"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestIssuerValidate(t *testing.T) {
	tests := map[string]struct {
		Modify         func(*cert.Issuer)
		ExpectedErrMsg error
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
			ExpectedErrMsg: cert.ErrInvalidSubject,
		},
		"No Issuing Key": {
			Modify: func(c *cert.Issuer) {
				delete(c.Keys, cert.IssuingKey)
			},
			ExpectedErrMsg: cert.ErrMissingKey,
		},
		"SigningKey": {
			Modify: func(c *cert.Issuer) {
				c.Keys[cert.SigningKey] = scrypto.KeyMeta{
					KeyVersion: 1,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte{2, 110, 1},
				}
			},
			ExpectedErrMsg: cert.ErrUnexpectedKey,
		},
		"EncryptionKey": {
			Modify: func(c *cert.Issuer) {
				c.Keys[cert.EncryptionKey] = scrypto.KeyMeta{
					KeyVersion: 1,
					Algorithm:  scrypto.Ed25519,
					Key:        []byte{1, 110, 1},
				}
			},
			ExpectedErrMsg: cert.ErrUnexpectedKey,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c := newIssuerCert(time.Now())
			test.Modify(&c)
			err := c.Validate()
			xtest.AssertErrorsIs(t, err, test.ExpectedErrMsg)
		})
	}
}
