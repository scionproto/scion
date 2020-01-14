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
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/proto"
)

// LocalInfo indicates whether something is always local.
type LocalInfo interface {
	IsSegLocal(ctx context.Context, src, dst addr.IA) (bool, error)
	IsParamsLocal(*query.Params) bool
}

// PathDB is a wrapper around the path db that handles retries and changes
// GetNextQuery behavior for usage in segfetcher.
type PathDB struct {
	pathdb.PathDB
	LocalInfo  LocalInfo
	RetrySleep time.Duration
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

// IsParamsLocal returns whether params is a core segment request.
func (i *CoreLocalInfo) IsParamsLocal(params *query.Params) bool {
	if len(params.SegTypes) != 1 {
		return false
	}
	if params.SegTypes[0] == proto.PathSegType_core {
		return true
	}
	if params.SegTypes[0] == proto.PathSegType_down {
		for _, ia := range params.StartsAt {
			if ia.I != i.LocalIA.I {
				return false
			}
		}
		for _, ia := range params.EndsAt {
			if ia.I != i.LocalIA.I {
				return false
			}
		}
		return true
	}
	return false
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

// IsParamsLocal returns whether params is a up segments request.
func (i *NonCoreLocalInfo) IsParamsLocal(params *query.Params) bool {
	return len(params.SegTypes) == 1 && params.SegTypes[0] == proto.PathSegType_up
}
