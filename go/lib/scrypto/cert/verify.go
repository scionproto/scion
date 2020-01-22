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

package cert

import (
	"errors"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
)

const (
	// ErrASValidityNotCovered indicates the AS certificate's validity period is
	// not covered by the issuer certificate's validity period.
	ErrASValidityNotCovered common.ErrMsg = "AS validity not covered"
	// ErrIssuerValidityNotCovered indicates the issuer certificate's validity
	// period is not covered by the TRC's validity period.
	ErrIssuerValidityNotCovered common.ErrMsg = "AS validity not covered"
	// ErrUnexpectedIssuer indicates another issuer is expected.
	ErrUnexpectedIssuer common.ErrMsg = "wrong issuer"
	// ErrUnexpectedCertificateVersion indicates another issuer certificate version is expected.
	ErrUnexpectedCertificateVersion common.ErrMsg = "wrong certificate version"
	// ErrUnexpectedTRCVersion indicates another TRC version is expected.
	ErrUnexpectedTRCVersion common.ErrMsg = "wrong TRC version"
	// ErrInvalidProtected indicates an invalid protected meta.
	ErrInvalidProtected common.ErrMsg = "invalid protected meta"
)

var (
	// ErrNotIssuing indicates that the subject of the issuer certificate is not
	// and issuing AS, and not allowed to self-sign the certificate.
	ErrNotIssuing = errors.New("not an issuing primary")
)

// ASVerifier verifies the AS certificate based on the trusted issuer certificate.
// The caller must ensure that the issuer certificate is verified, and that the
// AS certificate is valid and decoded from the signed AS certificate.
type ASVerifier struct {
	Issuer   *Issuer
	AS       *AS
	SignedAS *SignedAS
}

// Verify verifies the AS certificate.
func (v ASVerifier) Verify() error {
	p, err := v.SignedAS.EncodedProtected.Decode()
	if err != nil {
		return err
	}
	if err := v.checkIssuer(p); err != nil {
		return err
	}
	input := v.SignedAS.SigInput()
	meta := v.Issuer.Keys[IssuingKey]
	if err := scrypto.Verify(input, v.SignedAS.Signature, meta.Key, meta.Algorithm); err != nil {
		return err
	}
	return nil
}

func (v ASVerifier) checkIssuer(p ProtectedAS) error {
	if !v.Issuer.Subject.Equal(v.AS.Issuer.IA) {
		return common.NewBasicError(ErrUnexpectedIssuer, nil,
			"expected", v.AS.Issuer.IA, "actual", v.Issuer.Subject)
	}
	if v.Issuer.Version != v.AS.Issuer.CertificateVersion {
		return common.NewBasicError(ErrUnexpectedCertificateVersion, nil,
			"expected", v.AS.Issuer.CertificateVersion, "actual", v.Issuer.Version)
	}
	if !v.Issuer.Validity.Covers(*v.AS.Validity) {
		return common.NewBasicError(ErrASValidityNotCovered, nil,
			"issuer", v.Issuer.Validity, "as", v.AS.Validity)
	}
	expected := ProtectedAS{
		Algorithm:          v.Issuer.Keys[IssuingKey].Algorithm,
		CertificateVersion: v.Issuer.Version,
		IA:                 v.Issuer.Subject,
	}
	if p != expected {
		return common.NewBasicError(ErrInvalidProtected, nil, "expected", expected, "actual", p)
	}
	return nil
}

// IssuerVerifier verifies the issuer certificate based on the trusted TRC. The
// caller must ensure that the TRC is verified, and that the issuer certificate
// is valid and decoded from the signed issuer certificate.
type IssuerVerifier struct {
	TRC          *trc.TRC
	Issuer       *Issuer
	SignedIssuer *SignedIssuer
}

// Verify verifies the issuer certificate.
func (v IssuerVerifier) Verify() error {
	p, err := v.SignedIssuer.EncodedProtected.Decode()
	if err != nil {
		return err
	}
	if err := v.checkIssuer(p); err != nil {
		return err
	}
	input := v.SignedIssuer.SigInput()
	sig := v.SignedIssuer.Signature
	meta := v.TRC.PrimaryASes[v.Issuer.Subject.A].Keys[trc.IssuingGrantKey]
	if err := scrypto.Verify(input, sig, meta.Key, meta.Algorithm); err != nil {
		return err
	}
	return nil
}

func (v IssuerVerifier) checkIssuer(p ProtectedIssuer) error {
	meta, ok := v.TRC.PrimaryASes[v.Issuer.Subject.A]
	if !ok || !meta.Is(trc.Issuing) {
		return ErrNotIssuing
	}
	if v.TRC.Version != v.Issuer.Issuer.TRCVersion {
		return common.NewBasicError(ErrUnexpectedTRCVersion, nil,
			"expected", v.Issuer.Issuer.TRCVersion, "actual", v.TRC.Version)
	}
	if !v.TRC.Validity.Covers(*v.Issuer.Validity) {
		return common.NewBasicError(ErrIssuerValidityNotCovered, nil,
			"trc", v.TRC.Validity, "issuer", v.Issuer.Validity)
	}
	expected := ProtectedIssuer{
		Algorithm:  meta.Keys[trc.IssuingGrantKey].Algorithm,
		TRCVersion: v.TRC.Version,
	}
	if p != expected {
		return common.NewBasicError(ErrInvalidProtected, nil, "expected", expected, "actual", p)
	}
	return nil
}
