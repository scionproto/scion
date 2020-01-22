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

package keyconf

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strconv"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

var (
	// ErrContentsMismatch indicates that the contents of a loaded key do not
	// match the expected identifiers.
	ErrContentsMismatch = serrors.New("contents mismatch")
	// ErrNoAlgorithm indicates no algorithm was provided.
	ErrNoAlgorithm = serrors.New("no algorithm")
	// ErrNoKey indicates no key was provided.
	ErrNoKey = serrors.New("no key")
	// ErrReadFile indicates an error while reading a file.
	ErrReadFile = serrors.New("error reading file")
	// ErrUnsupportedUsage indicates the key usage is not known.
	ErrUnsupportedUsage = serrors.New("unsupported key usage")
	// ErrUnsupportedType indicates the key type is not known.
	ErrUnsupportedType = serrors.New("unsupported key type")
	// ErrWildcardIA indicates the IA contains a wildcard.
	ErrWildcardIA = serrors.New("wildcard IA")
)

const (
	hdrAlgorithm = "algorithm"
	hdrIA        = "ia"
	hdrNotAfter  = "not_after"
	hdrNotBefore = "not_before"
	hdrUsage     = "usage"
	hdrVersion   = "version"
)

// All supported key usages.
const (
	ASDecryptionKey Usage = "as-decrypt"
	ASRevocationKey Usage = "as-revocation"
	ASSigningKey    Usage = "as-signing"

	IssCertSigningKey Usage = "issuer-cert-signing"
	IssRevocationKey  Usage = "issuer-revocation"

	TRCIssuingGrantKey  Usage = "trc-issuing-grant"
	TRCVotingOfflineKey Usage = "trc-voting-offline"
	TRCVotingOnlineKey  Usage = "trc-voting-online"
)

// Usage describes how the key is intended to be used.
type Usage string

var usages = map[Usage]struct{}{
	ASSigningKey:        {},
	ASDecryptionKey:     {},
	ASRevocationKey:     {},
	IssCertSigningKey:   {},
	IssRevocationKey:    {},
	TRCVotingOnlineKey:  {},
	TRCVotingOfflineKey: {},
	TRCIssuingGrantKey:  {},
}

// UnmarshalText assigns the key usage if it is known. Otherwise ErrUnsupportedUsage.
func (u *Usage) UnmarshalText(text []byte) error {
	s := Usage(text)
	if _, ok := usages[s]; !ok {
		return serrors.WithCtx(ErrUnsupportedUsage, "input", string(text))
	}
	*u = s
	return nil
}

// Supported key types.
const (
	PublicKey    Type = "PUBLIC KEY"
	PrivateKey   Type = "PRIVATE KEY"
	SymmetricKey Type = "SYMMETRIC KEY"
)

// Type indicates the key type. (public|private|symmetric)
type Type string

// UnmarshalText assigns the key type if it is known. Otherwise ErrUnsupportedType.
func (t *Type) UnmarshalText(text []byte) error {
	s := Type(text)
	for _, keyType := range []Type{PublicKey, PrivateKey, SymmetricKey} {
		if keyType == s {
			*t = keyType
			return nil
		}
	}
	return serrors.WithCtx(ErrUnsupportedType, "input", string(text))
}

// ID identifies a specific key.
type ID struct {
	Usage   Usage
	IA      addr.IA
	Version scrypto.KeyVersion
}

// Key contains the key with additional metada.
//
// On disk, the key is encoded in PEM with a file name specific to the type,
// usage, and version of the key. The IA is prepended to public key filenames
// to avoid collisions.
//
// To see the resulting filename, check the example.
type Key struct {
	ID
	Type      Type
	Algorithm string
	Validity  scrypto.Validity
	Bytes     []byte
}

// LoadKeyFromFile loads the key from file and checks that the contained
// identifiers match.
func LoadKeyFromFile(file string, keyType Type, id ID) (Key, error) {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return Key{}, serrors.Wrap(ErrReadFile, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return Key{}, serrors.New("unable to parse PEM")
	}
	key, err := KeyFromPEM(block)
	if err != nil {
		return Key{}, serrors.WrapStr("unable to decode key", err)
	}
	if key.Type != keyType {
		return Key{}, serrors.WithCtx(ErrContentsMismatch, "field", "type",
			"expected", keyType, "actual", key.Type)
	}
	if !key.IA.Equal(id.IA) {
		return Key{}, serrors.WithCtx(ErrContentsMismatch, "field", "ia",
			"expected", id.IA, "actual", key.IA)
	}
	if key.Usage != id.Usage {
		return Key{}, serrors.WithCtx(ErrContentsMismatch, "field", "usage",
			"expected", id.Usage, "actual", key.Usage)
	}
	if key.Version != id.Version {
		return Key{}, serrors.WithCtx(ErrContentsMismatch, "field", "version",
			"expected", id.Version, "actual", key.Version)
	}
	return key, nil
}

// KeyFromPEM parses the PEM block.
func KeyFromPEM(block *pem.Block) (Key, error) {
	k := Key{}
	if err := k.Type.UnmarshalText([]byte(block.Type)); err != nil {
		return Key{}, serrors.WrapStr("unable to parse key type", err)
	}
	if err := k.Usage.UnmarshalText([]byte(block.Headers[hdrUsage])); err != nil {
		return Key{}, serrors.WrapStr("unable to parse key usage", err)
	}
	var ok bool
	if k.Algorithm, ok = block.Headers[hdrAlgorithm]; !ok {
		return Key{}, ErrNoAlgorithm
	}
	if err := parseTime(&k.Validity.NotBefore.Time, block.Headers[hdrNotBefore]); err != nil {
		return Key{}, serrors.WrapStr("unable to parse not_before time", err)
	}
	if err := parseTime(&k.Validity.NotAfter.Time, block.Headers[hdrNotAfter]); err != nil {
		return Key{}, serrors.WrapStr("unable to parse not_after time", err)
	}
	if err := parseVersion(&k.Version, block.Headers[hdrVersion]); err != nil {
		return Key{}, serrors.WrapStr("unable to parse key version", err)
	}
	if err := k.IA.UnmarshalText([]byte(block.Headers[hdrIA])); err != nil {
		return Key{}, serrors.WrapStr("unable to parse IA", err)
	}
	if k.IA.IsWildcard() {
		return Key{}, serrors.WithCtx(ErrWildcardIA, "input", block.Headers[hdrIA])
	}
	if block.Bytes == nil {
		return Key{}, ErrNoKey
	}
	k.Bytes = append([]byte(nil), block.Bytes...)
	return k, nil
}

// PEM encodes the key with metadata into a PEM block.
func (k Key) PEM() pem.Block {
	return pem.Block{
		Type: string(k.Type),
		Headers: map[string]string{
			hdrUsage:     string(k.Usage),
			hdrAlgorithm: k.Algorithm,
			hdrNotBefore: util.TimeToCompact(k.Validity.NotBefore.Truncate(time.Second)),
			hdrNotAfter:  util.TimeToCompact(k.Validity.NotAfter.Truncate(time.Second)),
			hdrVersion:   strconv.FormatUint(uint64(k.Version), 10),
			hdrIA:        k.IA.String(),
		},
		Bytes: append([]byte(nil), k.Bytes...),
	}
}

// File returns the key filename based on the metadata.
func (k Key) File() string {
	if k.Type == PrivateKey {
		return PrivateKeyFile(k.Usage, k.Version)
	}
	return PublicKeyFile(k.Usage, k.IA, k.Version)
}

func (k Key) String() string {
	key := "<redacted>"
	if k.Type == PublicKey {
		key = fmt.Sprintf("%x", k.Bytes)
	}
	return fmt.Sprintf("type: %s usage: %s version: %d ia: %s validity: %s algorithm: %s key: %s",
		k.Type, k.Usage, k.Version, k.IA, k.Validity, k.Algorithm, key,
	)
}

// PrivateKeyFile returns the file name for the private key with the provided
// intended usage and version.
func PrivateKeyFile(usage Usage, version scrypto.KeyVersion) string {
	return fmt.Sprintf("%s-v%d.key", usage, version)
}

// PublicKeyFile returns the file name for the public key with the provided
// intended usage and version.
func PublicKeyFile(usage Usage, ia addr.IA, version scrypto.KeyVersion) string {
	return fmt.Sprintf("%s-%s-v%d.pub", ia.FileFmt(true), usage, version)
}

func parseTime(t *time.Time, input string) error {
	var err error
	if *t, err = time.Parse(common.TimeFmtSecs, input); err != nil {
		return err
	}
	return nil
}

func parseVersion(v *scrypto.KeyVersion, input string) error {
	ver, err := strconv.ParseUint(input, 10, 64)
	if err != nil {
		return err
	}
	*v = scrypto.KeyVersion(ver)
	return nil
}
