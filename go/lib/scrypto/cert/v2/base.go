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
	"strconv"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

// Parsing errors with context.
const (
	// InvalidKeyType indicates an inexistent key type.
	InvalidKeyType = "invalid key type"
	// InvalidVersion indicates an invalid certificate version.
	InvalidVersion = "Invalid certificate version"
	// UnsupportedFormat indicates an invalid certificate format.
	UnsupportedFormat = "Unsupported certificate format"
)

// Validation errors with context.
const (
	// InvalidValidityPeriod indicates an invalid validity period.
	InvalidValidityPeriod = "invalid validity period"
	// InvalidSubject indicates that the subject contains a wildcard.
	InvalidSubject = "subject contains wildcard"
	// InvalidDistributionPoint indicates that the distribution point is a wildcard.
	InvalidDistributionPoint = "distribution point contains wildcard"
	// UnexpectedKey indicates that the certificate holds an excess key.
	UnexpectedKey = "unexpected key"
	// MissingKey indicates that the certificate is missing a key.
	MissingKey = "missing key"
)

// Parsing errors.
var (
	// ErrSubjectNotSet indicates Subject is not set.
	ErrSubjectNotSet = errors.New("Subject not set")
	// ErrVersionNotSet indicates Version is not set.
	ErrVersionNotSet = errors.New("Version not set")
	// ErrFormatVersionNotSet indicates FormatVersion is not set.
	ErrFormatVersionNotSet = errors.New("FormatVersion not set")
	// ErrDescriptionNotSet indicates Description is not set.
	ErrDescriptionNotSet = errors.New("Description not set")
	// ErrOptionalDistributionPointsNotSet indicates OptionalDistributionPoints is not set.
	ErrOptionalDistributionPointsNotSet = errors.New("OptionalDistributionPoints not set")
	// ErrValidityNotSet indicates Validity is not set.
	ErrValidityNotSet = errors.New("Validity not set")
	// ErrKeysNotSet indicates Keys is not set.
	ErrKeysNotSet = errors.New("Keys not set")
	// ErrIssuerNotSet indicates Issuer is not set.
	ErrIssuerNotSet = errors.New("Issuer not set")
	// ErrCertificateTypeNotSet indicates CertificateType is not set.
	ErrCertificateTypeNotSet = errors.New("CertificateType not set")
)

// Validation errors.
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
	Version scrypto.Version `json:"Version"`
	// FormatVersion is the certificate format version.
	FormatVersion FormatVersion `json:"FormatVersion"`
	// Description is a human-readable description of the certificate.
	Description string `json:"Description"`
	// OptionalDistributionPoints contains optional certificate revocation
	// distribution points.
	OptionalDistributionPoints []addr.IA `json:"OptionalDistributionPoints"`
	// Validity defines the validity period of the certificate.
	Validity *scrypto.Validity `json:"Validity"`
	// Keys holds all keys authenticated by this certificate.
	Keys map[KeyType]scrypto.KeyMeta `json:"Keys"`
}

// Validate validates the shared fields are set correctly.
func (b *Base) Validate() error {
	if b.Subject.IsWildcard() {
		return common.NewBasicError(InvalidSubject, nil, "subject", b.Subject)
	}
	if err := b.validateDistributionPoints(); err != nil {
		return err
	}
	if err := b.Validity.Validate(); err != nil {
		return common.NewBasicError(InvalidValidityPeriod, err, "validity", b.Validity)
	}
	return nil
}

func (b *Base) validateDistributionPoints() error {
	for _, ia := range b.OptionalDistributionPoints {
		if ia.IsWildcard() {
			return common.NewBasicError(InvalidDistributionPoint, nil, "IA", ia)
		}
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

func (b *Base) checkAllSet() error {
	switch {
	case b.Subject.IsZero():
		return ErrSubjectNotSet
	case b.Version == 0:
		return ErrVersionNotSet
	case b.FormatVersion == 0:
		return ErrFormatVersionNotSet
	case b.Description == "":
		return ErrDescriptionNotSet
	case b.OptionalDistributionPoints == nil:
		return ErrOptionalDistributionPointsNotSet
	case b.Validity == nil:
		return ErrValidityNotSet
	case b.Keys == nil:
		return ErrKeysNotSet
	}
	return nil
}

const (
	IssuingKeyJSON    = "Issuing"
	SigningKeyJSON    = "Signing"
	EncryptionKeyJSON = "Encryption"
	RevocationKeyJSON = "Revocation"
)

const (
	unknownKey KeyType = iota
	// IssuingKey is the issuing key type. It must only appear in issuer certificates.
	IssuingKey
	// SigningKey is the signing key type. It must only appear in AS certificates.
	SigningKey
	// EncryptionKey is the encryption key type. It must only appear in AS certificates.
	EncryptionKey
	// RevocationKey is the revocation key type. It may appear in AS and issuer certificates.
	RevocationKey
)

// KeyType indicates the type of the key authenticated by the certificate.
//
// Because KeyType is used as a map key, it cannot be a string type. (see:
// https://github.com/golang/go/issues/33298)
type KeyType int

// UnmarshalText allows KeyType to be used as a map key and do validation when parsing.
func (t *KeyType) UnmarshalText(b []byte) error {
	switch string(b) {
	case IssuingKeyJSON:
		*t = IssuingKey
	case SigningKeyJSON:
		*t = SigningKey
	case EncryptionKeyJSON:
		*t = EncryptionKey
	case RevocationKeyJSON:
		*t = RevocationKey
	default:
		return common.NewBasicError(InvalidKeyType, nil, "input", string(b))
	}
	return nil
}

// MarshalText is implemented to allow KeyType to be used as JSON map key. This
// must be a value receiver in order for KeyType fields in a struct to marshal
// correctly.
func (t KeyType) MarshalText() ([]byte, error) {
	switch t {
	case IssuingKey:
		return []byte(IssuingKeyJSON), nil
	case SigningKey:
		return []byte(SigningKeyJSON), nil
	case EncryptionKey:
		return []byte(EncryptionKeyJSON), nil
	case RevocationKey:
		return []byte(RevocationKeyJSON), nil
	}
	return nil, common.NewBasicError(InvalidKeyType, nil, "type", int(t))
}

// FormatVersion indicates the certificate format version. Currently, only format
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
