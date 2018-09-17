// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

package pathdb

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/proto"
)

// PathDB defines the interface that all PathDB backends have to implement.
type PathDB interface {
	// Insert inserts or updates a path segment. It returns the number of path segments
	// that have been inserted/updated.
	Insert(context.Context, *seg.PathSegment, []proto.PathSegType) (int, error)
	// InsertWithHPCfgIDs inserts or updates a path segment with a set of HPCfgIDs. It
	// returns the number of path segments that have been inserted/updated.
	InsertWithHPCfgIDs(context.Context, *seg.PathSegment, []proto.PathSegType, []*query.HPCfgID) (
		int, error)
	// Delete deletes a path segment with a given ID. Returns the number of deleted
	// path segments (0 or 1).
	Delete(context.Context, common.RawBytes) (int, error)
	// DeleteWithIntf deletes all path segments that contain a given interface. Returns
	// the number of path segments deleted.
	DeleteWithIntf(context.Context, query.IntfSpec) (int, error)
	// DeleteExpired deletes all paths segments that are expired, using now as a reference.
	// Returns the number of deleted segments.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
	// Get returns all path segment(s) matching the parameters specified.
	Get(context.Context, *query.Params) ([]*query.Result, error)
	// InsertNextQuery inserts or updates the timestamp nextQuery for the given dst.
	InsertNextQuery(ctx context.Context, dst addr.IA, nextQuery time.Time) (bool, error)
	// GetNextQuery returns the nextQuery timestamp for the given dst,
	// or nil if it hasn't been queried.
	GetNextQuery(ctx context.Context, dst addr.IA) (*time.Time, error)
}
