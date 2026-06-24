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
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
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
		// This test must not be run in parallel because we modify the CA
		// certificate struct.
		t.Run(name, func(t *testing.T) {
			ca := cppki.CAPolicy{
				Validity:             tc.Validity,
				Certificate:          chain[1],
				Signer:               tc.Signer(t),
				CurrentTime:          chain[0].NotBefore,
				ForceECDSAWithSHA512: tc.ForceECDSAWithSHA512,
			}
			ca.Certificate.PublicKey = ca.Signer.Public()
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

// mldsaSKID computes the SHA-1 of the DER-encoded SubjectPublicKeyInfo, matching
// the RFC 5280 §4.2.1.2 method (1) used by SubjectKeyID for ML-DSA keys.
func mldsaSKID(t *testing.T, pub *mldsa.PublicKey) []byte {
	t.Helper()
	raw, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	//nolint:staticcheck // SHA-1 SKID per RFC 5280 §4.2.1.2
	sum := sha1.Sum(raw)
	return sum[:]
}

// TestCreateChainMLDSA verifies that CreateChain works end-to-end with ML-DSA
// (MLDSA65) CA and AS keys, and that ValidateChain accepts the resulting chain.
func TestCreateChainMLDSA(t *testing.T) {
	// Generate ML-DSA-65 CA key pair (self-signed CA cert).
	caPriv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	caPub := caPriv.Public().(*mldsa.PublicKey)

	caSkid := mldsaSKID(t, caPub)

	// Build a SCION-conformant CA certificate subject.
	// Both Subject and Issuer must carry the OIDNameIA attribute.
	caSubject := pkix.Name{
		CommonName:   "1-ff00:0:110 ML-DSA CA",
		Organization: []string{"1-ff00:0:110"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: cppki.OIDNameIA, Value: "1-ff00:0:110"},
		},
	}

	caSerial := make([]byte, 20)
	_, err = rand.Read(caSerial)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	caNotBefore := now.Add(-time.Hour)
	caNotAfter := now.Add(24 * time.Hour)

	caTmpl := &x509.Certificate{
		Version:               3,
		SerialNumber:          new(big.Int).SetBytes(caSerial),
		Subject:               caSubject,
		NotBefore:             caNotBefore,
		NotAfter:              caNotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          caSkid,
		AuthorityKeyId:        caSkid, // self-signed: AKID == SKID
	}

	caRaw, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caRaw)
	require.NoError(t, err)

	// Generate ML-DSA-65 AS key pair.
	asPriv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	asPub := asPriv.Public().(*mldsa.PublicKey)

	// Build the CSR for the AS certificate.
	// Names (not ExtraNames) must be populated so that CreateChain's
	// `subject.ExtraNames = subject.Names` preserves the IA OID for marshaling.
	asSubject := pkix.Name{
		CommonName:   "1-ff00:0:110 ML-DSA AS",
		Organization: []string{"1-ff00:0:110"},
		Names: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "1-ff00:0:110 ML-DSA AS"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "1-ff00:0:110"},
			{Type: cppki.OIDNameIA, Value: "1-ff00:0:110"},
		},
	}
	csr := &x509.CertificateRequest{
		Subject:   asSubject,
		PublicKey: asPub,
	}

	ca := cppki.CAPolicy{
		Validity:    caNotAfter.Sub(caNotBefore) - 2*time.Hour,
		Certificate: caCert,
		Signer:      caPriv,
		CurrentTime: now,
	}

	chain, err := ca.CreateChain(csr)
	require.NoError(t, err, "CreateChain must succeed for ML-DSA keys")

	assert.Equal(t, x509.MLDSA65, chain[0].SignatureAlgorithm,
		"AS cert signature algorithm must be MLDSA65")
	assert.NoError(t, cppki.ValidateChain(chain),
		"ValidateChain must accept the ML-DSA chain")

	wantSKID, err := cppki.SubjectKeyID(asPub)
	require.NoError(t, err)
	assert.Equal(t, wantSKID, chain[0].SubjectKeyId,
		"AS cert SubjectKeyId must match cppki.SubjectKeyID(asPub)")
}
