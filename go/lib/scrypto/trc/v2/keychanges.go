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
	"github.com/scionproto/scion/go/lib/addr"
)

const (
	// InvalidKeyMeta indicates an invalid key metadata.
	InvalidKeyMeta = "invalid key meta"
	// InvalidKeyVersion indicates an invalid key version.
	InvalidKeyVersion = "invalid key version"
)

// ASToKeyMeta maps an AS to its key metadata for a single key type.
type ASToKeyMeta map[addr.AS]KeyMeta

// KeyChanges contains all new keys in a TRC update.
type KeyChanges struct {
	Modified map[KeyType]ASToKeyMeta
	Fresh    map[KeyType]ASToKeyMeta
}

func newKeyChanges() *KeyChanges {
	c := &KeyChanges{
		Modified: map[KeyType]ASToKeyMeta{
			OnlineKey:  make(ASToKeyMeta),
			OfflineKey: make(ASToKeyMeta),
			IssuingKey: make(ASToKeyMeta),
		},
		Fresh: map[KeyType]ASToKeyMeta{
			OnlineKey:  make(ASToKeyMeta),
			OfflineKey: make(ASToKeyMeta),
			IssuingKey: make(ASToKeyMeta),
		},
	}
	return c
}
