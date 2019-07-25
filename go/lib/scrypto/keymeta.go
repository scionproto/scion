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

package scrypto

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/scionproto/scion/go/lib/common"
)

var (
	// ErrKeyVersionNotSet indicates KeyVersion is not set.
	ErrKeyVersionNotSet = errors.New("key version not set")
	// ErrAlgorithmNotSet indicates the key algorithm is not set.
	ErrAlgorithmNotSet = errors.New("algorithm not set")
	// ErrKeyNotSet indicates the key is not set.
	ErrKeyNotSet = errors.New("key not set")
)

// KeyMeta holds the raw key with metadata.
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

// KeyVersion identifies a key version.
type KeyVersion uint64
