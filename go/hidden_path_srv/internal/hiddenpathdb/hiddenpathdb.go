// Copyright 2019 ETH Zurich, Anapaya Systems
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

package hiddenpathdb

import (
	"context"
	"database/sql"
	"io"
	"time"

	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpath"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
)

// Read defines all read operations of the hidden path DB.
type Read interface {
	// Get returns all path segment(s) matching the parameters specified.
	Get(context.Context, *Params) (query.Results, error)
}

// Write defines all write operations of the hidden path DB.
type Write interface {
	// Insert inserts or updates a hidden path segment. It returns the number of path segments
	// that have been inserted/updated.
	Insert(context.Context, *seg.Meta, hiddenpath.GroupIdSet) (pathdb.InsertStats, error)
	// Delete deletes all path segments that match the given query,
	// returning the number of deleted segments
	Delete(context.Context, *Params) (int, error)
	// DeleteExpired deletes all hidden path segments that are expired, using now as a reference.
	// Returns the number of deleted segments.
	DeleteExpired(context.Context, time.Time) (int, error)
}

// ReadWrite defines all read an write operations of the hidden path DB.
type ReadWrite interface {
	Read
	Write
}

type Transaction interface {
	ReadWrite
	Commit() error
	Rollback() error
}

// HiddenPathDB defines the interface that all HiddenPathDB backends have to implement
type HiddenPathDB interface {
	ReadWrite
	BeginTransaction(ctx context.Context, opts *sql.TxOptions) (Transaction, error)
	io.Closer
}

// Params contains the parameters with which the database can be queried.
type Params struct {
	GroupIds hiddenpath.GroupIdSet
	EndsAt   addr.IA
}
