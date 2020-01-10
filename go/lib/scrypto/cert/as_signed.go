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
	"unicode/utf8"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

// ErrIANotSet indicates the issuing ia is not set.
var ErrIANotSet = errors.New("ia not set")

type SignedAS struct {
	Encoded          EncodedAS           `json:"payload"`
	EncodedProtected EncodedProtectedAS  `json:"protected"`
	Signature        scrypto.JWSignature `json:"signature"`
}

// SigInput computes the signature input according to rfc7517 (see:
// https://tools.ietf.org/html/rfc7515#section-5.1)
func (s SignedAS) SigInput() []byte {
	return scrypto.JWSignatureInput(string(s.EncodedProtected), string(s.Encoded))
}

// EncodedAS is the the base64url encoded marshaled AS certificate. It is a
// string type to prevent json.Marshal from encoding it to base64 a second time.
type EncodedAS string

// EncodeAS encodes and returns the packed AS certificate.
func EncodeAS(c *AS) (EncodedAS, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return EncodedAS(scrypto.Base64.EncodeToString(b)), nil
}

// Decode returns the decoded Decode.
func (p EncodedAS) Decode() (*AS, error) {
	b, err := scrypto.Base64.DecodeString(string(p))
	if err != nil {
		return nil, err
	}
	var c AS
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// EncodedProtectedAS is the base64url encoded utf-8 metadata. It is a string
// type to prevent json.Marshal from encoding it to base64 a second time.
type EncodedProtectedAS string

// EncodeProtectedAS encodes the protected header.
func EncodeProtectedAS(p ProtectedAS) (EncodedProtectedAS, error) {
	// json.Marshal forces the necessary utf-8 encoding.
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return EncodedProtectedAS(scrypto.Base64.EncodeToString(b)), nil
}

// Decode decodes and return the protected header.
func (h EncodedProtectedAS) Decode() (ProtectedAS, error) {
	b, err := scrypto.Base64.DecodeString(string(h))
	if err != nil {
		return ProtectedAS{}, err
	}
	if !utf8.Valid(b) {
		return ProtectedAS{}, ErrNotUTF8
	}
	var meta ProtectedAS
	if err := json.Unmarshal(b, &meta); err != nil {
		return ProtectedAS{}, err
	}
	return meta, nil
}

// ProtectedAS is the signature metadata.
type ProtectedAS struct {
	Algorithm          string                   `json:"alg"`
	Crit               CritAS                   `json:"crit"`
	Type               SignatureTypeCertificate `json:"type"`
	CertificateVersion scrypto.Version          `json:"certificate_version"`
	IA                 addr.IA                  `json:"isd_as"`
}

// UnmarshalJSON checks that all fields are set.
func (p *ProtectedAS) UnmarshalJSON(b []byte) error {
	var alias protectedASAlias
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&alias); err != nil {
		return err
	}
	if err := alias.checkAllSet(); err != nil {
		return err
	}
	*p = ProtectedAS{
		Algorithm:          *alias.Algorithm,
		Type:               *alias.Type,
		CertificateVersion: *alias.CertificateVersion,
		IA:                 *alias.IA,
		Crit:               *alias.Crit,
	}
	return nil
}

type protectedASAlias struct {
	Algorithm          *string                   `json:"alg"`
	Type               *SignatureTypeCertificate `json:"type"`
	CertificateVersion *scrypto.Version          `json:"certificate_version"`
	IA                 *addr.IA                  `json:"isd_as"`
	Crit               *CritAS                   `json:"crit"`
}

func (p *protectedASAlias) checkAllSet() error {
	switch {
	case p.Algorithm == nil:
		return ErrAlgorithmNotSet
	case p.Type == nil:
		return ErrSignatureTypeNotSet
	case p.CertificateVersion == nil:
		return ErrIssuerCertificateVersionNotSet
	case p.IA == nil:
		return ErrIANotSet
	case p.Crit == nil:
		return ErrCritNotSet
	}
	return nil
}

const SignatureTypeCertificateJSON = "certificate"

// SignatureTypeCertificate indicates the public key is authenticated by an
// issuer certificate.
type SignatureTypeCertificate struct{}

// UnmarshalText checks the signature type is correct.
func (t *SignatureTypeCertificate) UnmarshalText(b []byte) error {
	if string(b) != SignatureTypeCertificateJSON {
		return common.NewBasicError(ErrInvalidSignatureType, nil, "input", string(b))
	}
	return nil
}

func (t SignatureTypeCertificate) MarshalText() ([]byte, error) {
	return []byte(SignatureTypeCertificateJSON), nil
}

var (
	critASFields        = []string{"type", "certificate_version", "isd_as"}
	packedCritFields, _ = json.Marshal(critASFields)
)

// CritAS is the "crit" section for the AS certificate (see:
// https://tools.ietf.org/html/rfc7515#section-4.1.11).
type CritAS struct{}

// UnmarshalJSON checks that all expected elements and no other are in the array.
func (CritAS) UnmarshalJSON(b []byte) error {
	return scrypto.CheckCrit(b, critASFields)
}

// MarshalJSON returns a json array with the expected crit elements.
func (CritAS) MarshalJSON() ([]byte, error) {
	return packedCritFields, nil
}
