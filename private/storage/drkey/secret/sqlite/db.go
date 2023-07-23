// Copyright 2022 ETH Zurich
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

package sqlite

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/private/storage/db"
)

const (
	SVSchemaVersion = 1
	SVSchema        = `
	CREATE TABLE DRKeySV (
		Protocol	INTEGER NOT NULL,
		EpochBegin 	INTEGER NOT NULL,
		EpochEnd 	INTEGER NOT NULL,
		PRIMARY KEY (Protocol, EpochBegin)
	);`
)

var _ drkey.SecretValueDB = (*Backend)(nil)

// Backend implements a SV DB with sqlite.
type Backend struct {
	*executor
	db *sql.DB
}

// NewBackend creates a database and prepares all statements.
func NewBackend(path string) (*Backend, error) {
	db, err := db.NewSqlite(path, SVSchema, SVSchemaVersion)
	if err != nil {
		return nil, err
	}
	b := &Backend{
		executor: &executor{
			db: db,
		},
		db: db,
	}
	return b, nil
}

// Close closes the database connection.
func (b *Backend) Close() error {
	return b.db.Close()
}

// SetMaxOpenConns sets the maximum number of open connections.
func (b *Backend) SetMaxOpenConns(maxOpenConns int) {
	b.db.SetMaxOpenConns(maxOpenConns)
}

// SetMaxIdleConns sets the maximum number of idle connections.
func (b *Backend) SetMaxIdleConns(maxIdleConns int) {
	b.db.SetMaxIdleConns(maxIdleConns)
}

type executor struct {
	sync.RWMutex
	db db.Sqler
}

const getSVStmt = `
SELECT EpochBegin, EpochEnd FROM DRKeySV
WHERE Protocol=?
AND EpochBegin<=? AND ?<EpochEnd
`

// GetValue takes the protocol and the time at which the SV must be
// valid and return such a SV.
func (e *executor) GetValue(
	ctx context.Context,
	meta drkey.SecretValueMeta,
	asSecret []byte,
) (drkey.SecretValue, error) {

	e.RLock()
	defer e.RUnlock()
	var epochBegin, epochEnd int

	valSecs := util.TimeToSecs(meta.Validity)
	err := e.db.QueryRowContext(ctx, getSVStmt, meta.ProtoId, valSecs, valSecs).Scan(&epochBegin,
		&epochEnd)
	if err != nil {
		if err != sql.ErrNoRows {
			return drkey.SecretValue{}, db.NewReadError("getting SV", err)
		}
		return drkey.SecretValue{}, drkey.ErrKeyNotFound
	}
	returningKey, err := drkey.DeriveSV(meta.ProtoId, drkey.NewEpoch(uint32(epochBegin),
		uint32(epochEnd)), asSecret)
	if err != nil {
		return drkey.SecretValue{}, err
	}
	return returningKey, nil
}

const insertSVStmt = `
INSERT OR IGNORE INTO DRKeySV (Protocol,EpochBegin, EpochEnd)
VALUES (?, ?, ?)
`

// InsertValue inserts a SV.
func (e *executor) InsertValue(
	ctx context.Context,
	proto drkey.Protocol,
	epoch drkey.Epoch,
) error {

	e.RLock()
	defer e.RUnlock()

	return db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, insertSVStmt, proto, uint32(epoch.NotBefore.Unix()),
			uint32(epoch.NotAfter.Unix()))
		if err != nil {
			return db.NewWriteError("inserting SV", err)
		}
		return nil
	})
}

const deleteExpiredSVStmt = `
DELETE FROM DRKeySV WHERE ? >= EpochEnd
`

// DeleteExpiredValues removes all expired SVs, i.e. all the keys
// which expiration time is strictly smaller than the cutoff
func (e *executor) DeleteExpiredValues(ctx context.Context, cutoff time.Time) (int, error) {

	e.RLock()
	defer e.RUnlock()

	return db.DeleteInTx(ctx, e.db, func(tx *sql.Tx) (sql.Result, error) {
		cutoffSecs := util.TimeToSecs(cutoff)
		return tx.ExecContext(ctx, deleteExpiredSVStmt, cutoffSecs)
	})
}
