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

package cppki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"math/big"
	"time"

	"github.com/scionproto/scion/go/lib/serrors"
)

// CAPolicy defines how AS certificates are generated.
type CAPolicy struct {
	// Validity defines the validity period of the create AS certificate.
	Validity time.Duration
	// Certificate is the CA certificate.
	Certificate *x509.Certificate
	// Signer holds the private key authenticated by the CA certificate.
	Signer crypto.Signer
	// CurrentTime indicates the signing time. If zero, the current time is
	// used.
	CurrentTime time.Time

	// ForceECDSAWithSHA512 forces the CA policy to use ECDSAWithSHA512 as the
	// signature algorithm for signing the issued certificate. This field
	// forces the old behavior extending the acceptable signature algorithms
	// in https://github.com/scionproto/scion/commit/df8565dc97cb6ef7c7925c26f23f3e9954ab2a97.
	//
	// Experimental: This field is experimental and will be subject to change.
	ForceECDSAWithSHA512 bool
}

// CreateChain takes the certificate request and creates a certificate chain.
// The request is assumed to be validated by the caller.
// The returned chain captures a reference to the CA certificate.
func (ca CAPolicy) CreateChain(csr *x509.CertificateRequest) ([]*x509.Certificate, error) {
	now := ca.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	caVal := Validity{NotBefore: ca.Certificate.NotBefore, NotAfter: ca.Certificate.NotAfter}
	asVal := Validity{NotBefore: now, NotAfter: now.Add(ca.Validity)}
	if !caVal.Covers(asVal) {
		return nil, serrors.New("AS certificate validity not covered", "ca", caVal, "as", asVal)
	}

	// Choose random serial number.
	serial := make([]byte, 20)
	if _, err := rand.Read(serial); err != nil {
		return nil, serrors.WrapStr("creating random serial number", err)
	}

	// ExtraNames are used for marshaling
	subject := csr.Subject
	subject.ExtraNames = subject.Names
	skid, err := SubjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, serrors.WrapStr("computing subject key ID", err)
	}

	// x509 stdlib selects the appropriate signature algorithm based on the curve.
	var signatureAlgo x509.SignatureAlgorithm
	if ca.ForceECDSAWithSHA512 {
		signatureAlgo = x509.ECDSAWithSHA512
	}
	tmpl := &x509.Certificate{
		SignatureAlgorithm: signatureAlgo,
		Version:            3,
		SerialNumber:       big.NewInt(0).SetBytes(serial),
		Subject:            subject,
		NotBefore:          asVal.NotBefore,
		NotAfter:           asVal.NotAfter,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageTimeStamping,
		},
		BasicConstraintsValid: false,
		SubjectKeyId:          skid,
		AuthorityKeyId:        ca.Certificate.SubjectKeyId,
	}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Certificate, csr.PublicKey, ca.Signer)
	if err != nil {
		return nil, serrors.WrapStr("creating AS certificate", err)
	}
	as, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, serrors.WrapStr("parse created AS certificate", err)
	}
	chain := []*x509.Certificate{as, ca.Certificate}
	if err := ValidateChain(chain); err != nil {
		return nil, serrors.WrapStr("created invalid AS certificate", err)
	}
	return chain, nil
}

func (ca CAPolicy) Equal(o CAPolicy) bool {
	var certEqual bool
	if ca.Certificate == nil || o.Certificate == nil {
		certEqual = ca.Certificate == o.Certificate
	} else {
		certEqual = ca.Certificate.Equal(o.Certificate)
	}
	return certEqual &&
		ca.Validity == o.Validity &&
		ca.CurrentTime == o.CurrentTime
}

// SubjectKeyID computes a subject key identifier for a given public key.
// The computed ID is the SHA-1 hash of the marshaled public key according to
// https://tools.ietf.org/html/rfc5280#section-4.2.1.2 (1)
func SubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		skid := sha1.Sum(elliptic.Marshal(k.Curve, k.X, k.Y))
		return skid[:], nil
	default:
		return nil, serrors.New("not supported")
	}
}
