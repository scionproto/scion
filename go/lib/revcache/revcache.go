// Copyright 2018 Anapaya Systems
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

package revcache

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
)

// Key denotes the key for the revocation cache.
type Key struct {
	ia   addr.IA
	ifid common.IFIDType
}

// NewKey creates a new key for the revocation cache.
func NewKey(ia addr.IA, ifid common.IFIDType) *Key {
	return &Key{
		ia:   ia,
		ifid: ifid,
	}
}

func (k Key) String() string {
	return fmt.Sprintf("%s#%s", k.ia, k.ifid)
}

// RevCache is a cache for revocations.
type RevCache interface {
	// Get item with key k from the cache. Returns the item or nil,
	// and a bool indicating whether the key was found.
	Get(k *Key) (*path_mgmt.SignedRevInfo, bool)
	// Insert inserts or updates the given revocation into the cache.
	// Returns whether an insert was performed.
	Insert(rev *path_mgmt.SignedRevInfo) bool
}

// GetAll gets all revocations for the given keys from the given revCache.
func GetAll(revCache RevCache, keys map[Key]struct{}) []*path_mgmt.SignedRevInfo {
	revs := make([]*path_mgmt.SignedRevInfo, 0, len(keys))
	for k := range keys {
		if revInfo, ok := revCache.Get(&k); ok {
			revs = append(revs, revInfo)
		}
	}
	return revs
}

// FilterNew filters the given revocations against the revCache, only the ones which are not in the
// cache are returned.
// Note: Modifies revocations slice.
func FilterNew(revCache RevCache,
	revocations []*path_mgmt.SignedRevInfo) []*path_mgmt.SignedRevInfo {

	filtered := revocations[:0]
	for _, r := range revocations {
		info, err := r.RevInfo()
		if err != nil {
			panic(fmt.Sprintf("Revocation should have been sanitized, err: %s", err))
		}
		existingRev, ok := revCache.Get(NewKey(info.IA(), info.IfID))
		if !ok {
			filtered = append(filtered, r)
			continue
		}
		existingInfo, err := existingRev.RevInfo()
		if err != nil {
			panic("Revocation should be sanitized in cache")
		}
		if newerInfo(info, existingInfo) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// newerInfo returns whether the received info is newer than the existing.
func newerInfo(existing, received *path_mgmt.RevInfo) bool {
	return !received.SameIntf(existing) ||
		received.Timestamp().After(existing.Timestamp())
}
