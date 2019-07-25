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
	"strconv"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

// Parsing errors with context.
const (
	// InvalidKeyType indicates an inexistent key type.
	InvalidKeyType = "invalid key type"
	// InvalidVersion indicates an invalid TRC version.
	InvalidVersion = "Invalid TRC version"
	// UnsupportedFormat indicates an invalid TRC format.
	UnsupportedFormat = "Unsupported TRC format"
)

// Validation errors
const (
	// InvalidValidityPeriod indicates an invalid validity period.
	InvalidValidityPeriod = "invalid validity period"
	// InvalidSubject indicates that the subject contains a wildcard.
	InvalidSubject = "subject contains wildcard"
	// UnexpectedKey indicates that the certificate holds an excess key.
	UnexpectedKey = "unexpected key"
	// MissingKey indicates that the certificate is missing a key.
	MissingKey = "missing key"
)

var (
	// ErrAlgorithmNotSet indicates the key algorithm is not set.
	ErrAlgorithmNotSet = errors.New("algorithm not set")
	// ErrKeyNotSet indicates the key is not set.
	ErrKeyNotSet = errors.New("key not set")
	// ErrKeyVersionNotSet indicates KeyVersion is not set.
	ErrKeyVersionNotSet = errors.New("key version not set")
)

// Base contains the shared fields between the issuer and AS certificate.
type Base struct {
	// Subject identifies the subject of the certificate.
	Subject addr.IA `json:"Subject"`
	// Version indicates the certificate version.
	Version Version `json:"Version"`
	// FormatVersion is the certificate format version.
	FormatVersion FormatVersion `json:"FormatVersion"`
	// Description is a human-readable description of the certificate.
	Description string `json:"Description"`
	// Validity defines the validity period of the certificate.
	Validity *scrypto.Validity `json:"Validity"`
	// Keys holds all keys authenticated by this certificate.
	Keys map[KeyType]KeyMeta `json:"Keys"`
}

// Validate validates the shared fields are set correctly.
func (b *Base) Validate() error {
	if b.Subject.IsWildcard() {
		return common.NewBasicError(InvalidSubject, nil, "subject", b.Subject)
	}
	if err := b.Validity.Validate(); err != nil {
		return common.NewBasicError(InvalidValidityPeriod, err, "validity", b.Validity)
	}
	return nil
}

func (b *Base) validateKeys(issuerCertificate bool) error {
	if err := b.checkKeyExistence(IssuingKey, issuerCertificate); err != nil {
		return err
	}
	if err := b.checkKeyExistence(SigningKey, !issuerCertificate); err != nil {
		return err
	}
	if err := b.checkKeyExistence(EncryptionKey, !issuerCertificate); err != nil {
		return err
	}
	return nil
}

func (b *Base) checkKeyExistence(keyType KeyType, shouldExist bool) error {
	_, ok := b.Keys[keyType]
	if ok && !shouldExist {
		return common.NewBasicError(UnexpectedKey, nil, "type", keyType)
	}
	if !ok && shouldExist {
		return common.NewBasicError(MissingKey, nil, "type", keyType)
	}
	return nil
}

// KeyMeta holds the key with metadata.
type KeyMeta struct {
	// KeyVersion identifies the key. It must change if the key changes, and
	// stay the same if the key does not change.
	KeyVersion KeyVersion `json:"KeyVersion"`
	// Algorithm indicates the algorithm associated with the key.
	Algorithm string `json:"Algorithm"`
	// Key is the raw public key.
	Key common.RawBytes `json:"Key"`
}

// UnmarshalJSON checks that all fields are set.
func (m *KeyMeta) UnmarshalJSON(b []byte) error {
	var alias keyMetaAlias
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&alias); err != nil {
		return err
	}
	if err := alias.checkAllSet(); err != nil {
		return err
	}
	*m = KeyMeta{
		KeyVersion: *alias.KeyVersion,
		Algorithm:  *alias.Algorithm,
		Key:        *alias.Key,
	}
	return nil
}

type keyMetaAlias struct {
	KeyVersion *KeyVersion      `json:"KeyVersion"`
	Algorithm  *string          `json:"Algorithm"`
	Key        *common.RawBytes `json:"Key"`
}

func (m *keyMetaAlias) checkAllSet() error {
	switch {
	case m.KeyVersion == nil:
		return ErrKeyVersionNotSet
	case m.Algorithm == nil:
		return ErrAlgorithmNotSet
	case m.Key == nil:
		return ErrKeyNotSet
	}
	return nil
}

// KeyVersion identifies a key for a given KeyType and ISD-AS.
type KeyVersion uint64

const (
	// IssuingKey is the issuing key type. It must only appear in issuer certificates.
	IssuingKey KeyType = "Issuing"
	// SigningKey is the signing key type. It must only appear in AS certificates.
	SigningKey KeyType = "Signing"
	// EncryptionKey is the encryption key type. It must only appear in AS certificates.
	EncryptionKey KeyType = "Encryption"
)

var _ json.Unmarshaler = (*KeyType)(nil)

// KeyType indicates the type of the key authenticated by the TRC. It can either
// be "Signing", "Encryption", or "Issuing".
type KeyType string

// UnmarshalJSON implements json.Unmarshaler.
func (t *KeyType) UnmarshalJSON(b []byte) error {
	switch KeyType(strings.Trim(string(b), `"`)) {
	case SigningKey:
		*t = SigningKey
	case EncryptionKey:
		*t = EncryptionKey
	case IssuingKey:
		*t = IssuingKey
	default:
		return common.NewBasicError(InvalidKeyType, nil, "input", string(b))
	}
	return nil
}

// Version identifies the version of a TRC. It cannot be
// marshalled/unmarshalled to/from scrypto.LatestVer.
type Version uint64

// UnmarshalJSON checks that the value is not scrypto.LatestVer.
func (v *Version) UnmarshalJSON(b []byte) error {
	parsed, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil {
		return err
	}
	if parsed == scrypto.LatestVer {
		return common.NewBasicError(InvalidVersion, nil, "ver", parsed)
	}
	*v = Version(parsed)
	return nil
}

// MarshalJSON checks that the value is not scrypto.LatestVer.
func (v Version) MarshalJSON() ([]byte, error) {
	if uint64(v) == scrypto.LatestVer {
		return nil, common.NewBasicError(InvalidVersion, nil, "ver", v)
	}
	return json.Marshal(uint64(v))
}

// FormatVersion indicates the TRC format version. Currently, only format
// version 1 is supported.
type FormatVersion uint8

// UnmarshalJSON checks that the FormatVersion is supported.
func (v *FormatVersion) UnmarshalJSON(b []byte) error {
	parsed, err := strconv.ParseUint(string(b), 10, 8)
	if err != nil {
		return err
	}
	if parsed != 1 {
		return common.NewBasicError(UnsupportedFormat, nil, "fmt", parsed)
	}
	*v = FormatVersion(parsed)
	return nil
}
