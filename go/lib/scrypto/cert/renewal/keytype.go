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

package renewal

import (
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/serrors"
)

// ErrInvalidKeyType indicates an inexistent key type.
var ErrInvalidKeyType = serrors.New("invalid key type")

// KeyType is the type of the key used in renewal. Can either be `signing` or
// `revocation`.
type KeyType string

// KeyType values
const (
	// SigningKey is the signing key type.
	SigningKey = KeyType(cert.SigningKeyJSON)
	// RevocationKey is the revocation key type.
	RevocationKey = KeyType(cert.RevocationKeyJSON)
)

// Validate validates that the KeyType has a valid value.
func (t KeyType) Validate() error {
	switch string(t) {
	case string(SigningKey), string(RevocationKey):
		return nil
	default:
		return serrors.WithCtx(ErrInvalidKeyType, "raw", string(t))
	}
}

// UnmarshalText allows to do validation on KeyType when parsing
func (t *KeyType) UnmarshalText(b []byte) error {
	*t = KeyType(b)
	if err := t.Validate(); err != nil {
		*t = ""
		return err
	}
	return nil
}

// MarshalText validates the KeyType before
func (t KeyType) MarshalText() ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return []byte(t), nil
}
