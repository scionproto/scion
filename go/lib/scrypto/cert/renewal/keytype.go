// Copyright 2020 Anapaya Systems
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

package renewal

import (
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/serrors"
)

// KeyType indicates the type of the key in a certificate renewal request.
//
// Because KeyType is used as a map key, it cannot be a string type. (see:
// https://github.com/golang/go/issues/33298)
type KeyType int

// KeyType values
const (
	unknownKey KeyType = iota
	// SigningKey is the signing key type. It must only appear in AS certificates.
	SigningKey = KeyType(cert.SigningKey)
	// RevocationKey is the revocation key type. It may appear in AS and issuer certificates.
	RevocationKey = KeyType(cert.RevocationKey)
)

// UnmarshalText allows KeyType to be used as a map key and do validation when parsing.
func (t *KeyType) UnmarshalText(b []byte) error {
	switch string(b) {
	case cert.SigningKeyJSON:
		*t = SigningKey
	case cert.RevocationKeyJSON:
		*t = RevocationKey
	default:
		return serrors.WithCtx(cert.ErrInvalidKeyType, "input", string(b))
	}
	return nil
}

// MarshalText is implemented to allow KeyType to be used as JSON map key. This
// must be a value receiver in order for KeyType fields in a struct to marshal
// correctly.
func (t KeyType) MarshalText() ([]byte, error) {
	switch t {
	case SigningKey:
		return []byte(cert.SigningKeyJSON), nil
	case RevocationKey:
		return []byte(cert.RevocationKeyJSON), nil
	}
	return nil, serrors.WithCtx(cert.ErrInvalidKeyType, "type", int(t))
}
