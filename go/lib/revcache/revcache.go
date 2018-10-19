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
	"context"
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
)

// Key denotes the key for the revocation cache.
type Key struct {
	IA   addr.IA
	IfId common.IFIDType
}

// NewKey creates a new key for the revocation cache.
func NewKey(ia addr.IA, ifId common.IFIDType) *Key {
	return &Key{
		IA:   ia,
		IfId: ifId,
	}
}

func (k Key) String() string {
	return fmt.Sprintf("%s#%s", k.IA, k.IfId)
}

// RevCache is a cache for revocations.
type RevCache interface {
	// Get item with key k from the cache. Returns the item or nil,
	// and a bool indicating whether the key was found.
	Get(ctx context.Context, k *Key) (*path_mgmt.SignedRevInfo, bool, error)
	// GetAll gets all revocations for the given keys.
	GetAll(ctx context.Context, keys map[Key]struct{}) ([]*path_mgmt.SignedRevInfo, error)
	// Insert inserts or updates the given revocation into the cache.
	// Returns whether an insert was performed.
	Insert(ctx context.Context, rev *path_mgmt.SignedRevInfo) (bool, error)
}

// FilterNew filters the given revocations against the revCache, only the ones which are not in the
// cache are returned.
// Note: Modifies revocations slice.
func FilterNew(ctx context.Context, revCache RevCache,
	revocations []*path_mgmt.SignedRevInfo) ([]*path_mgmt.SignedRevInfo, error) {

	filtered := revocations[:0]
	for _, r := range revocations {
		info, err := r.RevInfo()
		if err != nil {
			panic(fmt.Sprintf("Revocation should have been sanitized, err: %s", err))
		}
		existingRev, ok, err := revCache.Get(ctx, NewKey(info.IA(), info.IfID))
		if err != nil {
			return nil, err
		}
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
	return filtered, nil
}

// newerInfo returns whether the received info is newer than the existing.
func newerInfo(existing, received *path_mgmt.RevInfo) bool {
	return !received.SameIntf(existing) ||
		received.Timestamp().After(existing.Timestamp())
}
