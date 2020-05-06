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

package segreq

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/pathdb"
)

// PathDB is a wrapper around the path db that changes GetNextQuery behavior
// for usage in segfetcher.
type PathDB struct {
	pathdb.PathDB
	LocalInfo segfetcher.LocalInfo
}

func (db *PathDB) GetNextQuery(ctx context.Context, src, dst addr.IA,
	policy pathdb.PolicyHash) (time.Time, error) {
	if local, err := db.LocalInfo.IsSegLocal(ctx, src, dst); err != nil {
		return time.Time{}, err
	} else if local {
		return time.Now().Add(24 * time.Hour), nil
	}
	return db.PathDB.GetNextQuery(ctx, src, dst, policy)
}

// CoreLocalInfo implements local info for core PSes.
type CoreLocalInfo struct {
	CoreChecker CoreChecker
	LocalIA     addr.IA
}

// IsSegLocal returns whether the segments described by src and dst would be a
// core segments or a local down segment.
func (i *CoreLocalInfo) IsSegLocal(ctx context.Context, src, dst addr.IA) (bool, error) {
	// All local core and down segments.
	if dst.I == i.LocalIA.I {
		return true, nil
	}
	// All core segments
	isCore, err := i.CoreChecker.IsCore(ctx, dst)
	if err != nil {
		return false, err
	}
	return isCore, nil
}

// NonCoreLocalInfo is the local info for non core PSes.
type NonCoreLocalInfo struct {
	LocalIA addr.IA
}

// IsSegLocal checks if the segment described by src and dst is an up segment
// to the local core.
func (i *NonCoreLocalInfo) IsSegLocal(ctx context.Context, src, dst addr.IA) (bool, error) {
	// The validator should make sure that if we are at the source it can only
	// be an up segment.
	return i.LocalIA.Equal(src), nil
}
