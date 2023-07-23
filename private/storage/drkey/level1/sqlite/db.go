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
	// Level1SchemaVersion is the version of the SQLite schema understood by this backend.
	// Whenever changes to the schema are made, this version number should be increased
	// to prevent data corruption between incompatible database schemas.
	Level1SchemaVersion = 1
	// Level1Schema is the SQLite database layout.
	Level1Schema = `
	CREATE TABLE DRKeyLevel1 (
		SrcIsdID 	INTEGER NOT NULL,
		SrcAsID 	INTEGER NOT NULL,
		DstIsdID 	INTEGER NOT NULL,
		DstAsID 	INTEGER NOT NULL,
		Protocol	INTEGER NOT NULL,
		EpochBegin 	INTEGER NOT NULL,
		EpochEnd 	INTEGER NOT NULL,
		Key 		BLOB NOT NULL,
		PRIMARY KEY (SrcIsdID, SrcAsID, DstIsdID, DstAsID, Protocol, EpochBegin)
	);`
)

var _ drkey.Level1DB = (*Backend)(nil)

// Level1Backend implements a level 1 drkey DB with sqlite.
type Backend struct {
	*executor
	db *sql.DB
}

// NewLevel1Backend creates a database and prepares all statements.
func NewBackend(path string) (*Backend, error) {
	db, err := db.NewSqlite(path, Level1Schema, Level1SchemaVersion)
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

const getLevel1KeyStmt = `
SELECT EpochBegin, EpochEnd, Key FROM DRKeyLevel1
WHERE SrcIsdID=? AND SrcAsID=? AND DstIsdID=? AND DstAsID=?
AND Protocol=?
AND EpochBegin<=? AND ?<EpochEnd
`

// GetLevel1Key takes metadata information for the Level1 key and a timestamp at which it should be
// valid and returns the corresponding Level1Key.
func (e *executor) GetLevel1Key(
	ctx context.Context,
	meta drkey.Level1Meta,
) (drkey.Level1Key, error) {

	e.RLock()
	defer e.RUnlock()
	var epochBegin, epochEnd int
	var bytes []byte
	valSecs := util.TimeToSecs(meta.Validity)

	err := e.db.QueryRowContext(ctx, getLevel1KeyStmt, meta.SrcIA.ISD(), meta.SrcIA.AS(),
		meta.DstIA.ISD(), meta.DstIA.AS(), meta.ProtoId, valSecs,
		valSecs).Scan(&epochBegin, &epochEnd, &bytes)
	if err != nil {
		if err != sql.ErrNoRows {
			return drkey.Level1Key{}, db.NewReadError("getting Level1 key", err)
		}
		return drkey.Level1Key{}, drkey.ErrKeyNotFound
	}
	returningKey := drkey.Level1Key{
		ProtoId: meta.ProtoId,
		Epoch:   drkey.NewEpoch(uint32(epochBegin), uint32(epochEnd)),
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
	}
	copy(returningKey.Key[:], bytes)
	return returningKey, nil
}

const insertLevel1KeyStmt = `
INSERT OR IGNORE INTO DRKeyLevel1 (SrcIsdID, SrcAsID, DstIsdID, DstAsID,
	Protocol ,EpochBegin, EpochEnd, Key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`

// InsertLevel1Key inserts a Level1 key.
func (e *executor) InsertLevel1Key(ctx context.Context, key drkey.Level1Key) error {

	e.RLock()
	defer e.RUnlock()

	return db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(
			ctx,
			insertLevel1KeyStmt,
			key.SrcIA.ISD(),
			key.SrcIA.AS(),
			key.DstIA.ISD(),
			key.DstIA.AS(),
			key.ProtoId,
			uint32(key.Epoch.NotBefore.Unix()),
			uint32(key.Epoch.NotAfter.Unix()),
			key.Key[:],
		)
		if err != nil {
			return db.NewWriteError("inserting level1 key", err)
		}
		return nil
	})
}

const deleteExpiredLevel1KeysStmt = `
DELETE FROM DRKeyLevel1 WHERE ? >= EpochEnd
`

// DeleteExpiredLevel1Keys removes all expired Level1 key, i.e. all the keys
// which expiration time is strictly smaller than the cutoff
func (e *executor) DeleteExpiredLevel1Keys(ctx context.Context, cutoff time.Time) (int, error) {
	e.RLock()
	defer e.RUnlock()

	return db.DeleteInTx(ctx, e.db, func(tx *sql.Tx) (sql.Result, error) {
		cutoffSecs := util.TimeToSecs(cutoff)
		return tx.ExecContext(ctx, deleteExpiredLevel1KeysStmt, cutoffSecs)
	})
}
