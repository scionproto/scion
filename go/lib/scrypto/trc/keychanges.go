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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

const (
	// ErrInvalidKeyMeta indicates an invalid key metadata.
	ErrInvalidKeyMeta common.ErrMsg = "invalid key meta"
	// ErrInvalidKeyVersion indicates an invalid key version.
	ErrInvalidKeyVersion common.ErrMsg = "invalid key_version"
)

// ASToKeyMeta maps an AS to its key metadata for a single key type.
type ASToKeyMeta map[addr.AS]scrypto.KeyMeta

// KeyChanges contains all new keys in a TRC update.
type KeyChanges struct {
	Modified map[KeyType]ASToKeyMeta
	Fresh    map[KeyType]ASToKeyMeta
}

func newKeyChanges() *KeyChanges {
	c := &KeyChanges{
		Modified: map[KeyType]ASToKeyMeta{
			VotingOnlineKey:  make(ASToKeyMeta),
			VotingOfflineKey: make(ASToKeyMeta),
			IssuingGrantKey:  make(ASToKeyMeta),
		},
		Fresh: map[KeyType]ASToKeyMeta{
			VotingOnlineKey:  make(ASToKeyMeta),
			VotingOfflineKey: make(ASToKeyMeta),
			IssuingGrantKey:  make(ASToKeyMeta),
		},
	}
	return c
}

// Sensitive indicates whether the key changes are sensitive (i.e. any offline
// key changes).
func (c *KeyChanges) Sensitive() bool {
	return len(c.Fresh[VotingOfflineKey]) != 0 || len(c.Modified[VotingOfflineKey]) != 0
}

func (c *KeyChanges) insertModifications(as addr.AS, prev, next PrimaryAS) error {
	for keyType, meta := range next.Keys {
		prevMeta, ok := prev.Keys[keyType]
		if !ok {
			c.Fresh[keyType][as] = meta
			continue
		}
		modified, err := ValidateKeyUpdate(prevMeta, meta)
		if err != nil {
			return common.NewBasicError(ErrInvalidKeyMeta, err, "as", as, "key_type", keyType)
		}
		if modified {
			c.Modified[keyType][as] = meta
		}
	}
	return nil
}

// ValidateKeyUpdate validates that the prev and next key meta are consistent.
// If the algorithm and key are not modified by the update, the version must not
// change. If they are modified, the version must be increased by one. The
// return value indicates, whether the update is a modification.
func ValidateKeyUpdate(prev, next scrypto.KeyMeta) (bool, error) {
	modified := next.Algorithm != prev.Algorithm || !bytes.Equal(next.Key, prev.Key)
	switch {
	case modified && next.KeyVersion != prev.KeyVersion+1:
		return modified, common.NewBasicError(ErrInvalidKeyVersion, nil, "modified", modified,
			"expected", prev.KeyVersion+1, "actual", next.KeyVersion)
	case !modified && next.KeyVersion != prev.KeyVersion:
		return modified, common.NewBasicError(ErrInvalidKeyVersion, nil, "modified", modified,
			"expected", prev.KeyVersion, "actual", next.KeyVersion)
	}
	return modified, nil
}
