// Copyright 2019 ETH Zurich, Anapaya Systems AG
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

package adapter

import (
	"context"
	"database/sql"
	"time"

	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpath"
	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpathdb"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
)

var _ hiddenpathdb.HiddenPathDB = (*PathDBAdapter)(nil)

// PathDBAdapter implements the HiddenPathDB interface.
// It wraps an implementation of PathDB.
type PathDBAdapter struct {
	backend pathdb.PathDB
	*readWriter
}

type readWriter struct {
	backend pathdb.ReadWrite
}

// New returns a new PathDBAdapter with an implementation of PathDB as backend.
func New(pdb pathdb.PathDB) *PathDBAdapter {
	return &PathDBAdapter{
		backend:    pdb,
		readWriter: &readWriter{pdb},
	}
}

// Get fetches all the hidden path segments matching the given parameters
func (rw *readWriter) Get(ctx context.Context, params *hiddenpathdb.Params) (query.Results, error) {
	var queryParams *query.Params
	if params != nil {
		queryParams = &query.Params{
			HpCfgIDs: convertIds(params.GroupIds),
			EndsAt:   []addr.IA{params.EndsAt},
		}
	}
	return rw.backend.Get(ctx, queryParams)
}

// Insert inserts a hidden path segment into the the underlying PathDB
func (rw *readWriter) Insert(ctx context.Context, seg *seg.Meta,
	ids hiddenpath.GroupIdSet) (pathdb.InsertStats, error) {

	return rw.backend.InsertWithHPCfgIDs(ctx, seg, convertIds(ids))
}

// Delete deletes all path segments that match the given query,
// returning the number of deleted segments
func (rw *readWriter) Delete(ctx context.Context, params *hiddenpathdb.Params) (int, error) {
	var queryParams *query.Params
	if params != nil {
		queryParams = &query.Params{
			HpCfgIDs: convertIds(params.GroupIds),
			EndsAt:   []addr.IA{params.EndsAt},
		}
	}
	return rw.backend.Delete(ctx, queryParams)
}

// DeleteExpired deletes all hidden path segments that are expired, using now as a reference.
// Returns the number of deleted segments.
func (rw *readWriter) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	return rw.backend.DeleteExpired(ctx, now)
}

// BeginTransaction begins a database read-write transacation
func (a *PathDBAdapter) BeginTransaction(ctx context.Context, opts *sql.TxOptions) (
	hiddenpathdb.Transaction, error) {

	tx, err := a.backend.BeginTransaction(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &transaction{
		backend:    tx,
		readWriter: &readWriter{tx},
	}, nil
}

// Close closes the backend database
func (a *PathDBAdapter) Close() error {
	return a.backend.Close()
}

var _ hiddenpathdb.Transaction = (*transaction)(nil)

type transaction struct {
	backend pathdb.Transaction
	*readWriter
}

func (tx *transaction) Commit() error {
	return tx.backend.Commit()
}

func (tx *transaction) Rollback() error {
	return tx.backend.Rollback()
}

func convertIds(ids hiddenpath.GroupIdSet) []*query.HPCfgID {
	queryIds := make([]*query.HPCfgID, 0, len(ids))
	for id := range ids {
		queryId := &query.HPCfgID{
			IA: addr.IA{
				A: id.OwnerAS,
			},
			ID: uint64(id.Suffix),
		}
		queryIds = append(queryIds, queryId)
	}
	return queryIds
}
