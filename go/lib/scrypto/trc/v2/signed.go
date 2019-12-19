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

package trc

import (
	"bytes"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

const (
	// ErrInvalidCrit indicates that the value for the crit key is invalid.
	ErrInvalidCrit common.ErrMsg = "invalid crit"
	// ErrInvalidSignatureType indicates an invalid signature type.
	ErrInvalidSignatureType common.ErrMsg = "invalid signature type"
)

var (
	// ErrAlgorithmNotSet indicates the key algorithm is not set.
	ErrAlgorithmNotSet = errors.New("algorithm not set")
	// ErrASNotSet indicates the as is not set.
	ErrASNotSet = errors.New("as not set")
	// ErrCritNotSet indicates that crit is not set.
	ErrCritNotSet = errors.New("crit not set")
	// ErrNotUTF8 indicates an invalid encoding.
	ErrNotUTF8 = errors.New("not utf-8 encoded")
	// ErrSignatureTypeNotSet indicates the signature type is not set.
	ErrSignatureTypeNotSet = errors.New("signature type not set")
)

// Signed contains the packed TRC payload and the attached signatures.
type Signed struct {
	EncodedTRC Encoded     `json:"payload"`
	Signatures []Signature `json:"signatures"`
}

// ParseSigned parses the raw signed TRC.
func ParseSigned(raw []byte) (Signed, error) {
	var signed Signed
	if err := json.Unmarshal(raw, &signed); err != nil {
		return Signed{}, err
	}
	return signed, nil
}

// EncodeSigned encodes the signed TRC to raw bytes.
func EncodeSigned(signed Signed) ([]byte, error) {
	return json.Marshal(signed)
}

// Encoded is the the base64url encoded marshaled TRC. It is a string type to
// prevent json.Marshal from encoding it to base64 a second time.
type Encoded string

// Encode encodes and returns the packed TRC.
func Encode(trc *TRC) (Encoded, error) {
	b, err := json.Marshal(trc)
	if err != nil {
		return "", err
	}
	return Encoded(scrypto.Base64.EncodeToString(b)), nil
}

// Decode returns the decoded Decode.
func (p Encoded) Decode() (*TRC, error) {
	b, err := scrypto.Base64.DecodeString(string(p))
	if err != nil {
		return nil, err
	}
	var trc TRC
	if err := json.Unmarshal(b, &trc); err != nil {
		return nil, err
	}
	return &trc, nil
}

// Signature contains the signature and packed metadata for one single key.
type Signature struct {
	EncodedProtected EncodedProtected    `json:"protected"`
	Signature        scrypto.JWSignature `json:"signature"`
}

// EncodedProtected is the base64url encoded utf-8 metadata. It is a string type to
// prevent json.Marshal from encoding it to base64 a second time.
type EncodedProtected string

// EncodeProtected encodes the protected header.
func EncodeProtected(p Protected) (EncodedProtected, error) {
	// json.Marshal forces the necessary utf-8 encoding.
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return EncodedProtected(scrypto.Base64.EncodeToString(b)), nil
}

// Decode decodes and returns the protected header.
func (h EncodedProtected) Decode() (Protected, error) {
	b, err := scrypto.Base64.DecodeString(string(h))
	if err != nil {
		return Protected{}, err
	}
	if !utf8.Valid(b) {
		return Protected{}, ErrNotUTF8
	}
	var meta Protected
	if err := json.Unmarshal(b, &meta); err != nil {
		return Protected{}, err
	}
	return meta, nil
}

// Protected is the signature metadata.
type Protected struct {
	Algorithm  string             `json:"alg"`
	Type       SignatureType      `json:"type"`
	KeyType    KeyType            `json:"key_type"`
	KeyVersion scrypto.KeyVersion `json:"key_version"`
	AS         addr.AS            `json:"as"`
	Crit       Crit               `json:"crit"`
}

// UnmarshalJSON checks that all fields are set.
func (p *Protected) UnmarshalJSON(b []byte) error {
	var alias protectedAlias
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&alias); err != nil {
		return err
	}
	if err := alias.checkAllSet(); err != nil {
		return err
	}
	*p = Protected{
		Algorithm:  *alias.Algorithm,
		Type:       *alias.Type,
		KeyType:    *alias.KeyType,
		KeyVersion: *alias.KeyVersion,
		AS:         *alias.AS,
		Crit:       *alias.Crit,
	}
	return nil
}

type protectedAlias struct {
	Algorithm  *string             `json:"alg"`
	Type       *SignatureType      `json:"type"`
	KeyType    *KeyType            `json:"key_type"`
	KeyVersion *scrypto.KeyVersion `json:"key_version"`
	AS         *addr.AS            `json:"as"`
	Crit       *Crit               `json:"crit"`
}

func (p *protectedAlias) checkAllSet() error {
	switch {
	case p.Algorithm == nil:
		return ErrAlgorithmNotSet
	case p.Type == nil:
		return ErrSignatureTypeNotSet
	case p.KeyType == nil:
		return ErrKeyTypeNotSet
	case p.KeyVersion == nil:
		return ErrKeyVersionNotSet
	case p.AS == nil:
		return ErrASNotSet
	case p.Crit == nil:
		return ErrCritNotSet
	}
	return nil
}

const (
	// POPSignature indicates the purpose of the signature is to proof possession.
	POPSignature SignatureType = "proof_of_possession"
	// VoteSignature indicates the purpose of the signature is to cast a vote.
	VoteSignature SignatureType = "vote"
)

// SignatureType indicates the purpose of a signature.
type SignatureType string

// UnmarshalText checks that signature type is supported.
func (t *SignatureType) UnmarshalText(b []byte) error {
	switch SignatureType(b) {
	case POPSignature:
		*t = POPSignature
	case VoteSignature:
		*t = VoteSignature
	default:
		return common.NewBasicError(ErrInvalidSignatureType, nil, "input", string(b))
	}
	return nil
}

var (
	allCritFields       = []string{"type", "key_type", "key_version", "as"}
	packedCritFields, _ = json.Marshal(allCritFields)
)

var _ json.Unmarshaler = Crit{}
var _ json.Marshaler = Crit{}

// Crit is the "crit" section (see: https://tools.ietf.org/html/rfc7515#section-4.1.11).
type Crit struct{}

// UnmarshalJSON checks that all expected elements and no other are in the array.
func (c Crit) UnmarshalJSON(b []byte) error {
	return scrypto.CheckCrit(b, allCritFields)
}

// MarshalJSON returns a json array with the expected crit elements.
func (Crit) MarshalJSON() ([]byte, error) {
	return packedCritFields, nil
}

// SigInput computes the signature input according to rfc7517 (see:
// https://tools.ietf.org/html/rfc7515#section-5.1)
func SigInput(protected EncodedProtected, trc Encoded) common.RawBytes {
	return scrypto.JWSignatureInput(string(protected), string(trc))
}
