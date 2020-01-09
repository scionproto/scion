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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

var (
	// ErrIssuerTRCVersionNotSet indicates the issuer TRC version is not set.
	ErrIssuerTRCVersionNotSet = errors.New("issuer.trc_version not set")
)

// Issuer is the Issuer certificate.
type Issuer struct {
	Base
	// Issuer holds the TRC Version. Since the issuer certificate is
	// self-signed, the issuing AS in the TRC is the same as the subject of this
	// certificate.
	Issuer IssuerTRC `json:"issuer"`
	// CertificateType ensures the correct certificate type when marshalling.
	CertificateType TypeIssuer `json:"certificate_type"`
}

// Validate checks that the certificate is in a valid format.
func (c *Issuer) Validate() error {
	if err := c.Base.Validate(); err != nil {
		return err
	}
	if err := c.validateKeys(true); err != nil {
		return err
	}
	return nil
}

// UnmarshalJSON checks that all fields are set.
func (c *Issuer) UnmarshalJSON(b []byte) error {
	var cAlias issuerAlias
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cAlias); err != nil {
		return err
	}
	if err := cAlias.checkAllSet(); err != nil {
		return err
	}
	*c = Issuer{
		Base:            cAlias.Base,
		Issuer:          *cAlias.Issuer,
		CertificateType: *cAlias.CertificateType,
	}
	return nil
}

type issuerAlias struct {
	Base
	Issuer          *IssuerTRC  `json:"issuer"`
	CertificateType *TypeIssuer `json:"certificate_type"`
}

func (c *issuerAlias) checkAllSet() error {
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

// issuerTRCAlias is necessary to avoid an infinite recursion when unmarshalling.
type issuerTRCAlias IssuerTRC

// IssuerTRC identifies the TRC that authenticates the issuer certificate. The
// issuer certificate is self-signed, thus, the issuing AS and TRC ISD are
// implied by the subject.
type IssuerTRC struct {
	// TRCVersion is the version of the issuing TRC.
	TRCVersion scrypto.Version `json:"trc_version"`
}

// UnmarshalJSON checks that all fields are set.
func (i *IssuerTRC) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode((*issuerTRCAlias)(i)); err != nil {
		return err
	}
	return i.checkAllSet()
}

func (i *IssuerTRC) checkAllSet() error {
	if i.TRCVersion == 0 {
		return ErrIssuerTRCVersionNotSet
	}
	return nil
}

const TypeIssuerJSON = "issuer"

// TypeIssuer indicates an AS certificate.
type TypeIssuer struct{}

// UnmarshalText checks that the certificate type matches.
func (TypeIssuer) UnmarshalText(b []byte) error {
	if TypeIssuerJSON != string(b) {
		return common.NewBasicError(ErrInvalidCertificateType, nil,
			"expected", TypeIssuerJSON, "actual", string(b))
	}
	return nil
}

// MarshalText returns the AS certificate type.
func (TypeIssuer) MarshalText() ([]byte, error) {
	return []byte(TypeIssuerJSON), nil
}
