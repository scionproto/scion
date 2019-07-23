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
	"strings"
	"unicode/utf8"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

const (
	// InvalidCrit indicates that the value for the crit key is invalid.
	InvalidCrit = "invalid crit"
	// InvalidSignatureType indicates an invalid signature type.
	InvalidSignatureType = "invalid signature type"
)

var (
	// ErrASNotSet indicates the AS is not set.
	ErrASNotSet = errors.New("AS not set")
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

// Encoded is the the base64url encoded marshaled TRC.
type Encoded []byte

// Encode encodes and returns the packed TRC.
func Encode(trc *TRC) (Encoded, error) {
	b, err := json.Marshal(trc)
	if err != nil {
		return nil, err
	}
	return []byte(scrypto.Base64.EncodeToString(b)), nil
}

// Decode returns the decoded Decode.
func (p *Encoded) Decode() (*TRC, error) {
	b, err := scrypto.Base64.DecodeString(string(*p))
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
	EncodedProtected EncodedProtected `json:"protected"`
	Signature        []byte           `json:"signature"`
}

// EncodedProtected is the base64url encoded utf-8 metadata.
type EncodedProtected []byte

// EncodeProtected encodes the protected header.
func EncodeProtected(p Protected) (EncodedProtected, error) {
	// json.Marshal forces the necessary utf-8 encoding.
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return []byte(scrypto.Base64.EncodeToString(b)), nil
}

// Decode decodes and return the protected header.
func (h *EncodedProtected) Decode() (Protected, error) {
	b, err := scrypto.Base64.DecodeString(string(*h))
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
	Algorithm  string        `json:"alg"`
	Type       SignatureType `json:"Type"`
	KeyType    KeyType       `json:"KeyType"`
	KeyVersion KeyVersion    `json:"KeyVersion"`
	AS         addr.AS       `json:"AS"`
	Crit       Crit          `json:"crit"`
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
		Algorithm: *alias.Algorithm,
		Type:      *alias.Type,
		KeyType:   *alias.KeyType,
		AS:        *alias.AS,
		Crit:      *alias.Crit,
	}
	return nil
}

type protectedAlias struct {
	Algorithm  *string        `json:"alg"`
	Type       *SignatureType `json:"Type"`
	KeyType    *KeyType       `json:"KeyType"`
	KeyVersion *KeyVersion    `json:"KeyVersion"`
	AS         *addr.AS       `json:"AS"`
	Crit       *Crit          `json:"crit"`
}

func (p *protectedAlias) checkAllSet() error {
	switch {
	case p.Algorithm == nil:
		return ErrAlgorithmNotSet
	case p.Type == nil:
		return ErrSignatureTypeNotSet
	case p.KeyType == nil:
		return ErrTypeNotSet
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
	POPSignature SignatureType = "ProofOfPossession"
	// VoteSignature indicates the purpose of the signature is to cast a vote.
	VoteSignature SignatureType = "Vote"
)

var _ json.Unmarshaler = (*SignatureType)(nil)

// SignatureType indicates the purpose of a signature.
type SignatureType string

// UnmarshalJSON implements json.Unmarshaler.
func (t *SignatureType) UnmarshalJSON(b []byte) error {
	switch SignatureType(strings.Trim(string(b), `"`)) {
	case POPSignature:
		*t = POPSignature
	case VoteSignature:
		*t = VoteSignature
	default:
		return common.NewBasicError(InvalidSignatureType, nil, "input", string(b))
	}
	return nil
}

var _ json.Unmarshaler = Crit{}
var _ json.Marshaler = Crit{}

// Crit is the "crit" section (see: https://tools.ietf.org/html/rfc7515#section-4.1.11).
type Crit struct{}

// UnmarshalJSON checks that all expected elements and no other are in the array.
func (c Crit) UnmarshalJSON(b []byte) error {
	var l []string
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	if len(l) != 4 {
		return common.NewBasicError(InvalidCrit, nil, "len", len(l))
	}
	var seen int
	for _, val := range l {
		flag := c.entryToFlag(val)
		if flag == 0 {
			return common.NewBasicError(InvalidCrit, nil, "unknown", val)
		}
		seen |= flag
	}
	if !c.allSeen(seen) {
		return common.NewBasicError(InvalidCrit, nil, "input", string(b))
	}
	return nil
}

func (c Crit) entryToFlag(entry string) int {
	var flag int
	switch entry {
	case "Type":
		flag = 0x01
	case "KeyType":
		flag = 0x02
	case "KeyVersion":
		flag = 0x04
	case "AS":
		flag = 0x08
	}
	return flag
}

func (Crit) allSeen(flags int) bool {
	return flags == 0x0f
}

// MarshalJSON returns a json array with the expected crit elements.
func (Crit) MarshalJSON() ([]byte, error) {
	return []byte(`["Type", "AS", "KeyType", "KeyVersion"]`), nil
}
