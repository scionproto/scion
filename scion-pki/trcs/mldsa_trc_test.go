// Copyright 2026 SCION Association
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

package trcs_test

// TestMLDSASignedTRC proves that SCION TRC signing and verification work
// end-to-end with ML-DSA voting keys. It covers three scenarios:
//
//  1. A base TRC signed by a single ML-DSA sensitive voter and a single ML-DSA
//     regular voter.
//  2. A base TRC signed by two ML-DSA voters (one sensitive, one regular) using
//     all three ML-DSA parameter sets in a sub-test matrix.
//  3. A "mixed-signer" base TRC whose payload lists one ECDSA voter and one
//     ML-DSA voter per role (sensitive / regular), and both sign.  After
//     combining the four partial signatures with CombineSignedPayloads, the
//     combined SignedTRC is verified; both SignerInfos must pass
//     (*SignedTRC).Verify.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/scion-pki/certs"
	"github.com/scionproto/scion/scion-pki/trcs"
)

// buildMLDSACert creates a self-signed SCION voting certificate with an ML-DSA
// key.  certType must be cppki.Sensitive or cppki.Regular.
func buildMLDSACert(
	t *testing.T,
	certType cppki.CertType,
	params mldsa.Parameters,
	notBefore, notAfter time.Time,
) (*x509.Certificate, *mldsa.PrivateKey) {
	t.Helper()
	priv, err := mldsa.GenerateKey(params)
	require.NoError(t, err)
	rawCert, err := certs.CreateCertificate(certs.CertParams{
		Type: certType,
		Subject: pkix.Name{
			CommonName: "ML-DSA Test Voter",
		},
		PubKey:    priv.Public(),
		NotBefore: notBefore,
		NotAfter:  notAfter,
		CAKey:     priv,
	})
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(rawCert)
	require.NoError(t, err)
	return cert, priv
}

// buildECDSACert creates a self-signed SCION voting certificate with a P-256
// ECDSA key.
func buildECDSACert(
	t *testing.T,
	certType cppki.CertType,
	notBefore, notAfter time.Time,
) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rawCert, err := certs.CreateCertificate(certs.CertParams{
		Type: certType,
		Subject: pkix.Name{
			CommonName: "ECDSA Test Voter",
		},
		PubKey:    priv.Public(),
		NotBefore: notBefore,
		NotAfter:  notAfter,
		CAKey:     priv,
	})
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(rawCert)
	require.NoError(t, err)
	return cert, priv
}

// buildRootCert creates a self-signed CP-Root certificate.
func buildRootCert(
	t *testing.T,
	notBefore, notAfter time.Time,
) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rawCert, err := certs.CreateCertificate(certs.CertParams{
		Type: cppki.Root,
		Subject: pkix.Name{
			CommonName: "Root Test",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: cppki.OIDNameIA, Value: "1-1"},
			},
		},
		PubKey:    priv.Public(),
		NotBefore: notBefore,
		NotAfter:  notAfter,
		CAKey:     priv,
	})
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(rawCert)
	require.NoError(t, err)
	return cert
}

// buildBaseTRCPayload encodes a minimal base TRC containing the given certs.
// Quorum is 1.  All certs are expected to cover notBefore..notAfter.
func buildBaseTRCPayload(
	t *testing.T,
	certificates []*x509.Certificate,
	notBefore, notAfter time.Time,
) []byte {
	t.Helper()
	trc := cppki.TRC{
		Version: 1,
		ID: cppki.TRCID{
			ISD:    addr.ISD(1),
			Serial: 1,
			Base:   1,
		},
		Validity: cppki.Validity{
			NotBefore: notBefore.Add(30 * time.Second),
			NotAfter:  notAfter.Add(-30 * time.Second),
		},
		CoreASes:          []addr.AS{1},
		AuthoritativeASes: []addr.AS{1},
		Quorum:            1,
		Description:       "ML-DSA TRC test",
		Certificates:      certificates,
	}
	raw, err := trc.Encode()
	require.NoError(t, err)
	return raw
}

// TestMLDSASignedTRC verifies that a base TRC signed with ML-DSA keys passes
// (*SignedTRC).Verify (the genuine production verification path).
func TestMLDSASignedTRC(t *testing.T) {
	testCases := []struct {
		name   string
		params mldsa.Parameters
	}{
		{"MLDSA44", mldsa.MLDSA44()},
		{"MLDSA65", mldsa.MLDSA65()},
		{"MLDSA87", mldsa.MLDSA87()},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			notBefore := time.Now().Add(-1 * time.Minute)
			notAfter := notBefore.Add(1 * time.Hour)

			// Build one ML-DSA sensitive voter and one ML-DSA regular voter.
			sensitiveCert, sensitiveKey := buildMLDSACert(t, cppki.Sensitive, tc.params, notBefore, notAfter)
			regularCert, regularKey := buildMLDSACert(t, cppki.Regular, tc.params, notBefore, notAfter)
			rootCert := buildRootCert(t, notBefore, notAfter)

			// Encode the TRC payload listing both voters.
			pld := buildBaseTRCPayload(t, []*x509.Certificate{sensitiveCert, regularCert, rootCert}, notBefore, notAfter)

			// Sign with the sensitive voter.
			signedBySensitive, err := trcs.SignPayload(pld, sensitiveKey, sensitiveCert)
			require.NoError(t, err, "SignPayload for sensitive voter must succeed")

			// Sign with the regular voter.
			signedByRegular, err := trcs.SignPayload(pld, regularKey, regularCert)
			require.NoError(t, err, "SignPayload for regular voter must succeed")

			// Decode both partial signed TRCs.
			partialSensitive, err := cppki.DecodeSignedTRC(signedBySensitive)
			require.NoError(t, err)
			partialRegular, err := cppki.DecodeSignedTRC(signedByRegular)
			require.NoError(t, err)

			// Combine into a single SignedTRC with both SignerInfos.
			combined, err := trcs.CombineSignedPayloads(map[string]cppki.SignedTRC{
				"sensitive": partialSensitive,
				"regular":   partialRegular,
			})
			require.NoError(t, err, "CombineSignedPayloads must succeed")

			// Decode and verify the combined TRC.
			signedTRC, err := cppki.DecodeSignedTRC(combined)
			require.NoError(t, err, "DecodeSignedTRC must succeed")

			// Verify: this calls the genuine production path:
			//   (*SignedTRC).Verify -> verifyBase -> verifyAll -> verifySignerInfo ->
			//   cert.CheckSignature
			err = signedTRC.Verify(nil)
			assert.NoError(t, err, "Verify must pass for ML-DSA-signed base TRC (%s)", tc.name)
		})
	}
}

// TestMixedSignerTRC verifies that a base TRC signed by one ECDSA voter and
// one ML-DSA voter (per role) passes (*SignedTRC).Verify with both SignerInfos
// verified.
func TestMixedSignerTRC(t *testing.T) {
	notBefore := time.Now().Add(-1 * time.Minute)
	notAfter := notBefore.Add(1 * time.Hour)

	// Build certs: one ECDSA sensitive voter + one ML-DSA sensitive voter,
	// and one ECDSA regular voter + one ML-DSA regular voter.
	//
	// Quorum=1 means verification requires at least 1 sensitive and 1 regular
	// signature; but verifyBase calls verifyAll(detectNewVoters(classified{},
	// nextCerts)) which returns ALL voters.  So all four voters must sign.
	ecdsaSensitiveCert, ecdsaSensitiveKey := buildECDSACert(t, cppki.Sensitive, notBefore, notAfter)
	mldsaSensitiveCert, mldsaSensitiveKey := buildMLDSACert(t, cppki.Sensitive, mldsa.MLDSA65(), notBefore, notAfter)
	ecdsaRegularCert, ecdsaRegularKey := buildECDSACert(t, cppki.Regular, notBefore, notAfter)
	mldsaRegularCert, mldsaRegularKey := buildMLDSACert(t, cppki.Regular, mldsa.MLDSA65(), notBefore, notAfter)
	rootCert := buildRootCert(t, notBefore, notAfter)

	// The TRC payload lists all four voters.
	pld := buildBaseTRCPayload(t, []*x509.Certificate{
		ecdsaSensitiveCert,
		mldsaSensitiveCert,
		ecdsaRegularCert,
		mldsaRegularCert,
		rootCert,
	}, notBefore, notAfter)

	// Each voter signs the payload individually.
	signedECDSASensitive, err := trcs.SignPayload(pld, ecdsaSensitiveKey, ecdsaSensitiveCert)
	require.NoError(t, err)
	signedMLDSASensitive, err := trcs.SignPayload(pld, mldsaSensitiveKey, mldsaSensitiveCert)
	require.NoError(t, err)
	signedECDSARegular, err := trcs.SignPayload(pld, ecdsaRegularKey, ecdsaRegularCert)
	require.NoError(t, err)
	signedMLDSARegular, err := trcs.SignPayload(pld, mldsaRegularKey, mldsaRegularCert)
	require.NoError(t, err)

	// Decode partial signed TRCs.
	partialECDSASensitive, err := cppki.DecodeSignedTRC(signedECDSASensitive)
	require.NoError(t, err)
	partialMLDSASensitive, err := cppki.DecodeSignedTRC(signedMLDSASensitive)
	require.NoError(t, err)
	partialECDSARegular, err := cppki.DecodeSignedTRC(signedECDSARegular)
	require.NoError(t, err)
	partialMLDSARegular, err := cppki.DecodeSignedTRC(signedMLDSARegular)
	require.NoError(t, err)

	// Combine all four partial signatures into one SignedTRC.
	combined, err := trcs.CombineSignedPayloads(map[string]cppki.SignedTRC{
		"ecdsa-sensitive": partialECDSASensitive,
		"mldsa-sensitive": partialMLDSASensitive,
		"ecdsa-regular":   partialECDSARegular,
		"mldsa-regular":   partialMLDSARegular,
	})
	require.NoError(t, err, "CombineSignedPayloads must succeed for mixed-signer TRC")

	// Decode the combined TRC.
	signedTRC, err := cppki.DecodeSignedTRC(combined)
	require.NoError(t, err, "DecodeSignedTRC of combined mixed-signer TRC must succeed")

	// There must be exactly four SignerInfos (one per voter).
	require.Len(t, signedTRC.SignerInfos, 4, "combined TRC must have 4 SignerInfos")

	// Verify via the genuine production path: (*SignedTRC).Verify -> verifyBase
	// -> verifyAll -> verifySignerInfo -> cert.CheckSignature.
	// Both the ECDSA SignerInfo and the ML-DSA SignerInfo must verify.
	err = signedTRC.Verify(nil)
	assert.NoError(t, err, "Verify must pass for mixed ECDSA+ML-DSA signed base TRC")
}
