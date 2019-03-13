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
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb/query"
)

// Read defines all read operations of the path DB.
type Read interface {
	// Get returns all path segment(s) matching the parameters specified.
	Get(context.Context, *query.Params) (query.Results, error)
	// GetAll returns a channel that will provide all items in the path db. If the path db can't
	// prepare the query a nil channel and the error are returned. If the querying succeeded the the
	// channel will be filled with the segments in the database. If an error occurs during reading a
	// segment the error is pushed in the channel and the operation is aborted, that means that the
	// result might be incomplete. Note that implementations can spawn a goroutine to fill the
	// channel, which means the channel must be fully drained to guarantee the destruction of the
	// goroutine.
	GetAll(context.Context) (<-chan query.ResultOrErr, error)
	// GetNextQuery returns the nextQuery timestamp for the given dst,
	// or nil if it hasn't been queried.
	GetNextQuery(ctx context.Context, dst addr.IA) (*time.Time, error)
}

// Write defines all write operations of the path DB.
type Write interface {
	// Insert inserts or updates a path segment. It returns the number of path segments
	// that have been inserted/updated.
	Insert(context.Context, *seg.Meta) (int, error)
	// InsertWithHPCfgIDs inserts or updates a path segment with a set of HPCfgIDs. It
	// returns the number of path segments that have been inserted/updated.
	InsertWithHPCfgIDs(context.Context, *seg.Meta, []*query.HPCfgID) (int, error)
	// Delete deletes all path segments that matches the given query,
	// returning the number of deleted segments
	Delete(context.Context, *query.Params) (int, error)
	// DeleteExpired deletes all paths segments that are expired, using now as a reference.
	// Returns the number of deleted segments.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
	// Get returns all path segment(s) matching the parameters specified.
	// InsertNextQuery inserts or updates the timestamp nextQuery for the given dst.
	InsertNextQuery(ctx context.Context, dst addr.IA, nextQuery time.Time) (bool, error)
}

// ReadWrite defines all read an write operations of the path DB.
type ReadWrite interface {
	Read
	Write
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
}
