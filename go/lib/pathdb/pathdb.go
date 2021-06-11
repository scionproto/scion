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
	"database/sql"
	"io"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/cleaner"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/pathdb/query"
)

// InsertStats provides statistics about an insertion.
type InsertStats struct {
	// Inserted is the number of inserted entries.
	Inserted int
	// Updated is the number of updated entries.
	Updated int
}

// ReadWrite defines all read an write operations of the path DB.
type ReadWrite interface {
	// Get returns all path segment(s) matching the parameters specified.
	Get(context.Context, *query.Params) (query.Results, error)
	// GetAll returns a slice which contains all items in the path db. If the path db cannot
	// prepare the query, an empty slice and the error are returned. If the querying succeeds, the
	// slice will be filled with the segments in the database. If an error occurs during reading a
	// segment the error is appanded to the slice and the operation is aborted; thus, the
	// result might be incomplete.
	GetAll(context.Context) ([]query.ResultOrErr, error)
	// GetNextQuery returns the nextQuery timestamp for the given src-dst pair
	// and policy , or a zero time if it hasn't been queried.
	GetNextQuery(ctx context.Context, src, dst addr.IA, policy PolicyHash) (time.Time, error)
	// Insert inserts or updates a path segment. It returns the number of path segments
	// that have been inserted/updated.
	Insert(context.Context, *seg.Meta) (InsertStats, error)
	// InsertWithHPCfgIDs inserts or updates a path segment with a set of HPCfgIDs. It
	// returns the number of path segments that have been inserted/updated.
	InsertWithHPCfgIDs(context.Context, *seg.Meta, []*query.HPCfgID) (InsertStats, error)
	// DeleteExpired deletes all paths segments that are expired, using now as a reference.
	// Returns the number of deleted segments.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
	// InsertNextQuery inserts or updates the timestamp nextQuery for the given
	// src-dst pair and policy. Returns true if an insert/update happened or
	// false if the stored timestamp is already newer.
	InsertNextQuery(ctx context.Context, src, dst addr.IA, policy PolicyHash,
		nextQuery time.Time) (bool, error)
}

type Transaction interface {
	ReadWrite
	Commit() error
	Rollback() error
}

// PathDB defines the interface that all PathDB backends have to implement.
type PathDB interface {
	ReadWrite
	BeginTransaction(ctx context.Context, opts *sql.TxOptions) (Transaction, error)
	db.LimitSetter
	io.Closer
}

// NewCleaner creates a cleaner task that deletes expired segments.
func NewCleaner(db PathDB, namespace string) *cleaner.Cleaner {
	return cleaner.New(func(ctx context.Context) (int, error) {
		return db.DeleteExpired(ctx, time.Now())
	}, namespace)
}
