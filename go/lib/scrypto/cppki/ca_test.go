// Copyright 2020 Anapaya Systems
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

package cppki_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestCAPolicyCreateChain(t *testing.T) {
	chain := xtest.LoadChain(t, "testdata/verifychain/ISD1-ASff00_0_110.pem")
	csr := x509.CertificateRequest{
		Subject:   chain[0].Subject,
		PublicKey: chain[0].PublicKey,
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	testCases := map[string]struct {
		CSR                   func(t *testing.T) *x509.CertificateRequest
		Signer                func(t *testing.T) crypto.Signer
		Validity              time.Duration
		ForceECDSAWithSHA512  bool
		ExpectedSignatureAlgo x509.SignatureAlgorithm
		ErrAssertion          assert.ErrorAssertionFunc
	}{
		"valid p256": {
			CSR:                   func(t *testing.T) *x509.CertificateRequest { return &csr },
			Signer:                func(t *testing.T) crypto.Signer { return p256 },
			Validity:              chain[0].NotAfter.Sub(chain[0].NotBefore),
			ExpectedSignatureAlgo: x509.ECDSAWithSHA256,
			ErrAssertion:          assert.NoError,
		},
		"valid p384": {
			CSR: func(t *testing.T) *x509.CertificateRequest { return &csr },
			Signer: func(t *testing.T) crypto.Signer {
				p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return p384
			},
			Validity:              chain[0].NotAfter.Sub(chain[0].NotBefore),
			ExpectedSignatureAlgo: x509.ECDSAWithSHA384,
			ErrAssertion:          assert.NoError,
		},
		"valid p521": {
			CSR: func(t *testing.T) *x509.CertificateRequest { return &csr },
			Signer: func(t *testing.T) crypto.Signer {
				p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				require.NoError(t, err)
				return p521
			},
			Validity:              chain[0].NotAfter.Sub(chain[0].NotBefore),
			ExpectedSignatureAlgo: x509.ECDSAWithSHA512,
			ErrAssertion:          assert.NoError,
		},
		"valid legacy": {
			CSR:                   func(t *testing.T) *x509.CertificateRequest { return &csr },
			Signer:                func(t *testing.T) crypto.Signer { return p256 },
			Validity:              chain[0].NotAfter.Sub(chain[0].NotBefore),
			ForceECDSAWithSHA512:  true,
			ExpectedSignatureAlgo: x509.ECDSAWithSHA512,
			ErrAssertion:          assert.NoError,
		},
		"validity not covered": {
			CSR:          func(t *testing.T) *x509.CertificateRequest { return &csr },
			Signer:       func(t *testing.T) crypto.Signer { return p256 },
			Validity:     chain[1].NotAfter.Sub(chain[1].NotBefore) + time.Hour,
			ErrAssertion: assert.Error,
		},
		"unsupported subject key ID": {
			CSR: func(t *testing.T) *x509.CertificateRequest {
				c := csr
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				c.PublicKey = pub
				return &c
			},
			Signer:       func(t *testing.T) crypto.Signer { return p256 },
			Validity:     chain[0].NotAfter.Sub(chain[0].NotBefore),
			ErrAssertion: assert.Error,
		},
		"unsupported signer": {
			CSR: func(t *testing.T) *x509.CertificateRequest { return &csr },
			Signer: func(t *testing.T) crypto.Signer {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				return priv
			},
			Validity:     chain[0].NotAfter.Sub(chain[0].NotBefore),
			ErrAssertion: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ca := cppki.CAPolicy{
				Validity:             tc.Validity,
				Certificate:          chain[1],
				Signer:               tc.Signer(t),
				CurrentTime:          chain[0].NotBefore,
				ForceECDSAWithSHA512: tc.ForceECDSAWithSHA512,
			}
			gen, err := ca.CreateChain(tc.CSR(t))
			tc.ErrAssertion(t, err)
			if err != nil {
				return
			}
			assert.NoError(t, cppki.ValidateChain(gen))
			assert.Equal(t, chain[1], gen[1])
			assert.Equal(t, tc.ExpectedSignatureAlgo, gen[0].SignatureAlgorithm)
			assert.Equal(t, chain[0].Subject, gen[0].Subject)
			assert.Equal(t, chain[0].PublicKey, gen[0].PublicKey)
			assert.Equal(t, chain[0].PublicKeyAlgorithm, gen[0].PublicKeyAlgorithm)
			assert.Equal(t, chain[0].Version, gen[0].Version)
			assert.Equal(t, chain[0].Issuer, gen[0].Issuer)
			assert.Equal(t, chain[0].NotBefore, gen[0].NotBefore)
			assert.Equal(t, chain[0].NotAfter, gen[0].NotAfter)
			assert.Equal(t, chain[0].KeyUsage, gen[0].KeyUsage)
			assert.ElementsMatch(t, chain[0].Extensions, gen[0].Extensions)
			assert.ElementsMatch(t, chain[0].ExtKeyUsage, gen[0].ExtKeyUsage)
			assert.Equal(t, chain[0].SubjectKeyId, gen[0].SubjectKeyId)
			assert.Equal(t, chain[0].AuthorityKeyId, gen[0].AuthorityKeyId)
		})
	}
}

func TestSubjectKeyID(t *testing.T) {
	// Check computation is compatible with openssl
	chain := xtest.LoadChain(t, "testdata/verifychain/ISD1-ASff00_0_110.pem")
	skid, err := cppki.SubjectKeyID(chain[0].PublicKey.(crypto.PublicKey))
	require.NoError(t, err)
	assert.Equal(t, chain[0].SubjectKeyId, skid)
}
