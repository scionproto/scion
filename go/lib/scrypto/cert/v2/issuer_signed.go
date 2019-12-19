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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

var (
	// ErrTRCVersionNotSet indicates the TRC version is not set.
	ErrTRCVersionNotSet = errors.New("trc_version not set")
)

type SignedIssuer struct {
	Encoded          EncodedIssuer          `json:"payload"`
	EncodedProtected EncodedProtectedIssuer `json:"protected"`
	Signature        scrypto.JWSignature    `json:"signature"`
}

// SigInput computes the signature input according to rfc7517 (see:
// https://tools.ietf.org/html/rfc7515#section-5.1)
func (s SignedIssuer) SigInput() []byte {
	return scrypto.JWSignatureInput(string(s.EncodedProtected), string(s.Encoded))
}

// ParseSignedIssuer parses the raw signed issuer certificate.
func ParseSignedIssuer(raw []byte) (SignedIssuer, error) {
	var signed SignedIssuer
	if err := json.Unmarshal(raw, &signed); err != nil {
		return SignedIssuer{}, err
	}
	return signed, nil
}

// EncodeSignedIssuer encodes the signed issuer certificate to raw bytes.
func EncodeSignedIssuer(signed SignedIssuer) ([]byte, error) {
	return json.Marshal(signed)
}

// EncodedIssuer is the the base64url encoded marshaled issuer certificate. It
// is a string type to prevent json.Marshal from encoding it to base64 a second
// time.
type EncodedIssuer string

// EncodeIssuer encodes and returns the packed issuer certificate.
func EncodeIssuer(c *Issuer) (EncodedIssuer, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return EncodedIssuer(scrypto.Base64.EncodeToString(b)), nil
}

// Decode returns the decoded Decode.
func (p EncodedIssuer) Decode() (*Issuer, error) {
	b, err := scrypto.Base64.DecodeString(string(p))
	if err != nil {
		return nil, err
	}
	var c Issuer
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// EncodedProtectedIssuer is the base64url encoded utf-8 metadata. It is a
// string type to prevent json.Marshal from encoding it to base64 a second time.
type EncodedProtectedIssuer string

// EncodeProtectedIssuer encodes the protected header.
func EncodeProtectedIssuer(p ProtectedIssuer) (EncodedProtectedIssuer, error) {
	// json.Marshal forces the necessary utf-8 encoding.
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return EncodedProtectedIssuer(scrypto.Base64.EncodeToString(b)), nil
}

// Decode decodes and return the protected header.
func (h EncodedProtectedIssuer) Decode() (ProtectedIssuer, error) {
	b, err := scrypto.Base64.DecodeString(string(h))
	if err != nil {
		return ProtectedIssuer{}, err
	}
	if !utf8.Valid(b) {
		return ProtectedIssuer{}, ErrNotUTF8
	}
	var meta ProtectedIssuer
	if err := json.Unmarshal(b, &meta); err != nil {
		return ProtectedIssuer{}, err
	}
	return meta, nil
}

// ProtectedIssuer is the signature metadata.
type ProtectedIssuer struct {
	Algorithm  string           `json:"alg"`
	Type       SignatureTypeTRC `json:"type"`
	TRCVersion scrypto.Version  `json:"trc_version"`
	Crit       CritIssuer       `json:"crit"`
}

// UnmarshalJSON checks that all fields are set.
func (p *ProtectedIssuer) UnmarshalJSON(b []byte) error {
	var alias protectedIssuerAlias
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&alias); err != nil {
		return err
	}
	if err := alias.checkAllSet(); err != nil {
		return err
	}
	*p = ProtectedIssuer{
		Algorithm:  *alias.Algorithm,
		Type:       *alias.Type,
		TRCVersion: *alias.TRCVersion,
		Crit:       *alias.Crit,
	}
	return nil
}

type protectedIssuerAlias struct {
	Algorithm  *string           `json:"alg"`
	Type       *SignatureTypeTRC `json:"type"`
	TRCVersion *scrypto.Version  `json:"trc_version"`
	Crit       *CritIssuer       `json:"crit"`
}

func (p *protectedIssuerAlias) checkAllSet() error {
	switch {
	case p.Algorithm == nil:
		return ErrAlgorithmNotSet
	case p.Type == nil:
		return ErrSignatureTypeNotSet
	case p.TRCVersion == nil:
		return ErrTRCVersionNotSet
	case p.Crit == nil:
		return ErrCritNotSet
	}
	return nil
}

const SignatureTypeTRCJSON = "trc"

// SignatureTypeTRC indicates the public key is authenticated by an
// issuer certificate.
type SignatureTypeTRC struct{}

// UnmarshalText checks the signature type is correct.
func (t *SignatureTypeTRC) UnmarshalText(b []byte) error {
	if string(b) != SignatureTypeTRCJSON {
		return common.NewBasicError(ErrInvalidSignatureType, nil, "input", string(b))
	}
	return nil
}

func (t SignatureTypeTRC) MarshalText() ([]byte, error) {
	return []byte(SignatureTypeTRCJSON), nil
}

var (
	critIssuerFields          = []string{"type", "trc_version"}
	packedCritIssuerFields, _ = json.Marshal(critIssuerFields)
)

// CritIssuer is the "crit" section for the issuer certificate (see:
// https://tools.ietf.org/html/rfc7515#section-4.1.11).
type CritIssuer struct{}

// UnmarshalJSON checks that all expected elements and no other are in the array.
func (CritIssuer) UnmarshalJSON(b []byte) error {
	return scrypto.CheckCrit(b, critIssuerFields)
}

// MarshalJSON returns a json array with the expected crit elements.
func (CritIssuer) MarshalJSON() ([]byte, error) {
	return packedCritIssuerFields, nil
}
