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
	// Level2SchemaVersion is the version of the SQLite schema understood by this backend.
	// Whenever changes to the schema are made, this version number should be increased
	// to prevent data corruption between incompatible database schemas.
	Level2SchemaVersion = 1
	// Level2Schema is the SQLite database layout.
	Level2Schema = `
	CREATE TABLE ASHost (
		Protocol	INTEGER NOT NULL,
		SrcIsdID	INTEGER NOT NULL,
		SrcAsID	INTEGER NOT NULL,
		DstIsdID	INTEGER NOT NULL,
		DstAsID	INTEGER NOT NULL,
		DstHostIP	TEXT,
		EpochBegin	INTEGER NOT NULL,
		EpochEnd	INTEGER NOT NULL,
		Key	BLOB NOT NULL,
		PRIMARY KEY (Protocol, SrcIsdID, SrcAsID,` +
		` DstIsdID, DstAsID, DstHostIP, EpochBegin)
	);

	CREATE TABLE HostAS (
		Protocol	INTEGER NOT NULL,
		SrcIsdID	INTEGER NOT NULL,
		SrcAsID	INTEGER NOT NULL,
		DstIsdID	INTEGER NOT NULL,
		DstAsID	INTEGER NOT NULL,
		SrcHostIP	TEXT,
		EpochBegin	INTEGER NOT NULL,
		EpochEnd	INTEGER NOT NULL,
		Key	BLOB NOT NULL,
		PRIMARY KEY (Protocol, SrcIsdID, SrcAsID,` +
		` DstIsdID, DstAsID, SrcHostIP, EpochBegin)
	);

	CREATE TABLE HostHost (
		Protocol	INTEGER NOT NULL,
		SrcIsdID	INTEGER NOT NULL,
		SrcAsID	INTEGER NOT NULL,
		DstIsdID	INTEGER NOT NULL,
		DstAsID	INTEGER NOT NULL,
		SrcHostIP	TEXT,
		DstHostIP	TEXT,
		EpochBegin	INTEGER NOT NULL,
		EpochEnd	INTEGER NOT NULL,
		Key	BLOB NOT NULL,
		PRIMARY KEY (Protocol, SrcIsdID, SrcAsID,` +
		` DstIsdID, DstAsID, SrcHostIP, DstHostIP, EpochBegin)
	);
	`
)

var _ drkey.Level2DB = (*Backend)(nil)

// Backend implements a level 2 drkey DB with sqlite.
type Backend struct {
	*executor
	db *sql.DB
}

// NewBackend creates a database and prepares all statements.
func NewBackend(path string) (*Backend, error) {
	db, err := db.NewSqlite(path, Level2Schema, Level2SchemaVersion)
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

const getASHostKeyStmt = `
SELECT EpochBegin, EpochEnd, Key
FROM ASHost WHERE Protocol=? AND SrcIsdID=? AND SrcAsID=? AND
DstIsdID=? AND DstAsID=? AND DstHostIP=?
AND EpochBegin<=? AND ?<EpochEnd
`

// GetASHostKey takes metadata information for the ASHost key and a timestamp
// at which it should be valid and returns the corresponding key.
func (e *executor) GetASHostKey(
	ctx context.Context,
	meta drkey.ASHostMeta) (drkey.ASHostKey, error) {
	e.RLock()
	defer e.RUnlock()
	var epochBegin int
	var epochEnd int
	var bytes []byte

	valSecs := util.TimeToSecs(meta.Validity)

	err := e.db.QueryRowContext(ctx, getASHostKeyStmt,
		meta.ProtoId,
		meta.SrcIA.ISD(), meta.SrcIA.AS(),
		meta.DstIA.ISD(), meta.DstIA.AS(),
		meta.DstHost, valSecs, valSecs,
	).Scan(&epochBegin, &epochEnd, &bytes)
	if err != nil {
		if err != sql.ErrNoRows {
			return drkey.ASHostKey{}, db.NewReadError("getting ASHost key", err)
		}
		return drkey.ASHostKey{}, drkey.ErrKeyNotFound
	}
	returningKey := drkey.ASHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   drkey.NewEpoch(uint32(epochBegin), uint32(epochEnd)),
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		DstHost: meta.DstHost,
	}
	copy(returningKey.Key[:], bytes)
	return returningKey, nil
}

const insertASHostKeyStmt = `
INSERT OR IGNORE INTO ASHost (Protocol, SrcIsdID, SrcAsID, DstIsdID, DstAsID,
DstHostIP, EpochBegin, EpochEnd, Key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`

// InsertASHostKey inserts a ASHost key.
func (e *executor) InsertASHostKey(ctx context.Context, key drkey.ASHostKey) error {
	e.RLock()
	defer e.RUnlock()

	return db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, insertASHostKeyStmt,
			key.ProtoId,
			key.SrcIA.ISD(), key.SrcIA.AS(),
			key.DstIA.ISD(), key.DstIA.AS(),
			key.DstHost,
			uint32(key.Epoch.NotBefore.Unix()), uint32(key.Epoch.NotAfter.Unix()),
			key.Key[:],
		)

		if err != nil {
			return db.NewWriteError("inserting ASHost key", err)
		}
		return nil
	})
}

const getHostASKeyStmt = `
SELECT EpochBegin, EpochEnd, Key
FROM HostAS WHERE Protocol=? AND SrcIsdID=? AND SrcAsID=? AND
DstIsdID=? AND DstAsID=? AND SrcHostIP=?
AND EpochBegin<=? AND ?<EpochEnd
`

// GetHostASKey takes metadata information for the HostAS key and a timestamp
// at which it should be valid and returns the corresponding key.
func (e *executor) GetHostASKey(
	ctx context.Context,
	meta drkey.HostASMeta) (drkey.HostASKey, error) {
	e.RLock()
	defer e.RUnlock()

	var epochBegin int
	var epochEnd int
	var bytes []byte

	valSecs := util.TimeToSecs(meta.Validity)

	err := e.db.QueryRowContext(ctx, getHostASKeyStmt,
		meta.ProtoId,
		meta.SrcIA.ISD(), meta.SrcIA.AS(),
		meta.DstIA.ISD(), meta.DstIA.AS(),
		meta.SrcHost,
		valSecs, valSecs,
	).Scan(&epochBegin, &epochEnd, &bytes)
	if err != nil {
		if err != sql.ErrNoRows {
			return drkey.HostASKey{}, db.NewReadError("getting Host-AS key", err)
		}
		return drkey.HostASKey{}, drkey.ErrKeyNotFound
	}
	returningKey := drkey.HostASKey{
		ProtoId: meta.ProtoId,
		Epoch:   drkey.NewEpoch(uint32(epochBegin), uint32(epochEnd)),
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		SrcHost: meta.SrcHost,
	}
	copy(returningKey.Key[:], bytes)
	return returningKey, nil
}

const insertHostASKeyStmt = `
INSERT OR IGNORE INTO HostAS (Protocol, SrcIsdID, SrcAsID, DstIsdID, DstAsID,
SrcHostIP, EpochBegin, EpochEnd, Key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`

// InsertHostASKey inserts a HostAS key.
func (e *executor) InsertHostASKey(ctx context.Context, key drkey.HostASKey) error {
	e.RLock()
	defer e.RUnlock()

	return db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, insertHostASKeyStmt,
			key.ProtoId,
			key.SrcIA.ISD(), key.SrcIA.AS(),
			key.DstIA.ISD(), key.DstIA.AS(),
			key.SrcHost,
			uint32(key.Epoch.NotBefore.Unix()), uint32(key.Epoch.NotAfter.Unix()),
			key.Key[:],
		)
		if err != nil {
			return db.NewWriteError("inserting Host-As key", err)
		}
		return nil
	})
}

const getHostHostKeyStmt = `
SELECT EpochBegin, EpochEnd, Key
FROM HostHost WHERE Protocol=? AND SrcIsdID=? AND SrcAsID=? AND
DstIsdID=? AND DstAsID=? AND SrcHostIP=? AND DstHostIP=?
AND EpochBegin<=? AND ?<EpochEnd
`

// GetHostHostKey takes metadata information for the HostHost key and a timestamp
// at which it should be valid and returns the corresponding key.
func (e *executor) GetHostHostKey(
	ctx context.Context,
	meta drkey.HostHostMeta) (drkey.HostHostKey, error) {
	e.RLock()
	defer e.RUnlock()

	var epochBegin int
	var epochEnd int
	var bytes []byte

	valSecs := util.TimeToSecs(meta.Validity)

	err := e.db.QueryRowContext(ctx, getHostHostKeyStmt,
		meta.ProtoId,
		meta.SrcIA.ISD(), meta.SrcIA.AS(),
		meta.DstIA.ISD(), meta.DstIA.AS(),
		meta.SrcHost, meta.DstHost,
		valSecs, valSecs,
	).Scan(&epochBegin, &epochEnd, &bytes)
	if err != nil {
		if err != sql.ErrNoRows {
			return drkey.HostHostKey{}, db.NewReadError("getting Host-Host key", err)
		}
		return drkey.HostHostKey{}, drkey.ErrKeyNotFound
	}
	returningKey := drkey.HostHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   drkey.NewEpoch(uint32(epochBegin), uint32(epochEnd)),
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		SrcHost: meta.SrcHost,
		DstHost: meta.DstHost,
	}
	copy(returningKey.Key[:], bytes)
	return returningKey, nil
}

const insertHostHostKeyStmt = `
INSERT OR IGNORE INTO HostHost (Protocol, SrcIsdID, SrcAsID, DstIsdID, DstAsID,
SrcHostIP, DstHostIP, EpochBegin, EpochEnd, Key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

// InsertHostHostKey inserts a HostHost key.
func (e *executor) InsertHostHostKey(ctx context.Context, key drkey.HostHostKey) error {
	e.RLock()
	defer e.RUnlock()

	return db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, insertHostHostKeyStmt,
			key.ProtoId,
			key.SrcIA.ISD(), key.SrcIA.AS(),
			key.DstIA.ISD(), key.DstIA.AS(),
			key.SrcHost, key.DstHost,
			uint32(key.Epoch.NotBefore.Unix()), uint32(key.Epoch.NotAfter.Unix()),
			key.Key[:],
		)
		if err != nil {
			return db.NewWriteError("inserting Host-Host key", err)
		}
		return nil
	})
}

const deleteExpiredASHostKeysStmt = `
DELETE FROM ASHost WHERE ? >= EpochEnd;
`

// DeleteExpiredASHostKeys removes all expired AS-Host keys, i.e. those keys
// which expiration time is strictly less than the cutoff
func (e *executor) DeleteExpiredASHostKeys(ctx context.Context, cutoff time.Time) (int, error) {
	e.RLock()
	defer e.RUnlock()

	return db.DeleteInTx(ctx, e.db, func(tx *sql.Tx) (sql.Result, error) {
		cutoffSecs := util.TimeToSecs(cutoff)
		return tx.ExecContext(ctx, deleteExpiredASHostKeysStmt, cutoffSecs)
	})
}

const deleteExpiredHostASKeysStmt = `
DELETE FROM HostAS WHERE ? >= EpochEnd;
`

// DeleteExpiredHostASKeys removes all expired Host-AS keys, i.e. those keys
// which expiration time is strictly less than the cutoff
func (e *executor) DeleteExpiredHostASKeys(ctx context.Context, cutoff time.Time) (int, error) {
	e.RLock()
	defer e.RUnlock()

	return db.DeleteInTx(ctx, e.db, func(tx *sql.Tx) (sql.Result, error) {
		cutoffSecs := util.TimeToSecs(cutoff)
		return tx.ExecContext(ctx, deleteExpiredHostASKeysStmt, cutoffSecs)
	})
}

const deleteExpiredHostHostKeysStmt = `
DELETE FROM HostHost WHERE ? >= EpochEnd;
`

// DeleteExpiredHostHostKeys removes all expired Host-Host keys, i.e. those keys
// which expiration time is strictly less than the cutoff
func (e *executor) DeleteExpiredHostHostKeys(ctx context.Context, cutoff time.Time) (int, error) {
	e.RLock()
	defer e.RUnlock()

	return db.DeleteInTx(ctx, e.db, func(tx *sql.Tx) (sql.Result, error) {
		cutoffSecs := util.TimeToSecs(cutoff)
		return tx.ExecContext(ctx, deleteExpiredHostHostKeysStmt, cutoffSecs)
	})
}
