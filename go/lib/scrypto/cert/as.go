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
	"bytes"
	"encoding/json"
	"errors"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

const (
	// ErrWildcardIssuer indicates the issuer is a wildcard IA.
	ErrWildcardIssuer common.ErrMsg = "issuer.ia is wildcard"
	// ErrIssuerDifferentISD indicates that the issuing AS is in a different ISD.
	ErrIssuerDifferentISD common.ErrMsg = "issuing.ia in different ISD"
	// ErrInvalidCertificateType indicates the certificate type is invalid.
	ErrInvalidCertificateType common.ErrMsg = "invalid certificate_type"
)

var (
	// ErrIssuerIANotSet indicates the issuer ia is not set.
	ErrIssuerIANotSet = errors.New("issuer.ia not set")
	// ErrIssuerCertificateVersionNotSet indicates the issuer certificate version is not set.
	ErrIssuerCertificateVersionNotSet = errors.New("issuer.certificate_version not set")
)

// AS is the AS certificate.
type AS struct {
	Base
	// Issuer holds the identifiers of the issuing issuer certificate.
	Issuer IssuerCertID `json:"issuer"`
	// CertificateType ensures the correct certificate type when marshalling.
	CertificateType TypeAS `json:"certificate_type"`
}

// Validate checks that the certificate is in a valid format.
func (c *AS) Validate() error {
	if err := c.Base.Validate(); err != nil {
		return err
	}
	if err := c.validateKeys(false); err != nil {
		return err
	}
	if c.Issuer.IA.IsWildcard() {
		return common.NewBasicError(ErrWildcardIssuer, nil, "issuer", c.Issuer.IA)
	}
	if c.Subject.I != c.Issuer.IA.I {
		return common.NewBasicError(ErrIssuerDifferentISD, nil,
			"subject", c.Subject, "issuer", c.Issuer.IA)
	}
	return nil
}

// UnmarshalJSON checks that all fields are set.
func (c *AS) UnmarshalJSON(b []byte) error {
	var cAlias asAlias
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cAlias); err != nil {
		return err
	}
	if err := cAlias.checkAllSet(); err != nil {
		return err
	}
	*c = AS{
		Base:            cAlias.Base,
		Issuer:          *cAlias.Issuer,
		CertificateType: *cAlias.CertificateType,
	}
	return nil
}

type asAlias struct {
	Base
	Issuer          *IssuerCertID `json:"issuer"`
	CertificateType *TypeAS       `json:"certificate_type"`
}

func (c *asAlias) checkAllSet() error {
	if err := c.Base.checkAllSet(); err != nil {
		return err
	}
	switch {
	case c.Issuer == nil:
		return ErrIssuerNotSet
	case c.CertificateType == nil:
		return ErrCertificateTypeNotSet
	}
	return nil
}

// issuerCertIDAlias is necessary to avoid an infinite recursion when unmarshalling.
type issuerCertIDAlias IssuerCertID

// IssuerCertID identifies the issuer certificate that authenticates the AS certificate.
type IssuerCertID struct {
	// IA is the subject of the issuing issuer certificate.
	IA addr.IA `json:"isd_as"`
	// CertificateVersion is the version of the issuing issuer certificate.
	CertificateVersion scrypto.Version `json:"certificate_version"`
}

// UnmarshalJSON checks that all fields are set.
func (i *IssuerCertID) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode((*issuerCertIDAlias)(i)); err != nil {
		return err
	}
	return i.checkAllSet()
}

func (i *IssuerCertID) checkAllSet() error {
	switch {
	case i.IA.IsWildcard():
		return ErrIssuerIANotSet
	case i.CertificateVersion == 0:
		return ErrIssuerCertificateVersionNotSet
	}
	return nil
}

const TypeASJSON = "as"

// TypeAS indicates an AS certificate.
type TypeAS struct{}

// UnmarshalText checks that the certificate type matches.
func (TypeAS) UnmarshalText(b []byte) error {
	if TypeASJSON != string(b) {
		return common.NewBasicError(ErrInvalidCertificateType, nil,
			"expected", TypeASJSON, "actual", string(b))
	}
	return nil
}

// MarshalText returns the AS certificate type.
func (TypeAS) MarshalText() ([]byte, error) {
	return []byte(TypeASJSON), nil
}
