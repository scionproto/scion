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

package hiddenpath

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Store is the interface to the hidden segment database.
type Store interface {
	// Get gets the segments that end at the given IA and are in one of the given
	// hidden path groups.
	Get(context.Context, addr.IAInt, []GroupID) ([]*seg.Meta, error)
	// Put puts the given segments in the database and associates them with the
	// given hidden path group ID.
	Put(context.Context, []*seg.Meta, GroupID) error
}

// Storer implements the path DB interface for a hidden segments.
type Storer struct {
	DB pathdb.DB
}

// Get returns segments from the store using a db provider.
func (s *Storer) Get(ctx context.Context, ia addr.IAInt,
	groups []GroupID) ([]*seg.Meta, error) {

	res, err := s.DB.Get(ctx, &query.Params{
		EndsAt:     []addr.IAInt{ia},
		HPGroupIDs: convert(groups),
	})
	if err != nil {
		return nil, err
	}
	return res.SegMetas(), nil
}

// Put stores segments in the store using a db provider.
func (s *Storer) Put(ctx context.Context, segs []*seg.Meta, g GroupID) error {
	var errs serrors.List
	for _, seg := range segs {
		_, e := s.DB.InsertWithHPGroupIDs(ctx, seg, convert([]GroupID{g}))
		if e != nil {
			errs = append(errs, e)
		}
	}
	return errs.ToError()
}

func convert(ids []GroupID) (ret []uint64) {
	for _, id := range ids {
		ret = append(ret, id.ToUint64())
	}
	return
}
