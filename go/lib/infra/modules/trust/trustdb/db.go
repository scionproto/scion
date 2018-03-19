// Copyright 2018 ETH Zurich
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

// Package trustdb provides wrappers for SQL calls for managing a database
// containing TRCs and Certificate Chains.
//
// KNOWN ISSUE: DB methods serialize to/dezerialize from JSON on each call.
// For performance penalty details, check the benchmarks in the test file.
package trustdb

import (
	"context"
	"database/sql"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/sqlite"
)

const (
	SchemaVersion = 1
	Schema        = ` CREATE TABLE TRCs (
		IsdID INTEGER NOT NULL,
		Version INTEGER NOT NULL,
		Data TEXT NOT NULL,
		PRIMARY KEY (IsdID, Version)
	);

	CREATE TABLE Chains (
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		Version INTEGER NOT NULL,
		Data TEXT NOT NULL,
		PRIMARY KEY (IsdID, AsID, Version)
	);
	`

	TRCsTable   = "TRCs"
	ChainsTable = "Chains"
)

const (
	getChainVersionStr = `
			SELECT Data FROM Chains
			WHERE IsdID=? AND AsID=? AND Version=?
		`
	getChainMaxVersionStr = `
			SELECT Data FROM Chains
			WHERE IsdID=? AND AsID=? AND Version=(SELECT Max(Version) FROM Chains)
		`
	insertChainStr = `
			INSERT INTO Chains (IsdID, AsID, Version, Data) VALUES (?, ?, ?, ?)
		`
	getTRCVersionStr = `
			SELECT Data FROM TRCs
			WHERE IsdID=? AND Version=?
		`
	getTRCMaxVersionStr = `
			SELECT Data FROM TRCs
			WHERE IsdID=? AND Version=(SELECT Max(Version) FROM TRCs)
		`
	insertTRCStr = `
			INSERT INTO TRCs (IsdID, Version, Data) VALUES (?, ?, ?)
		`
)

// DB is a database containing TRCs and Certificate Chains, stored in JSON format.
//
// On errors, GetXxx methods return nil and the error. If no error occurred,
// but the database query yielded 0 results, the first returned value is nil.
// GetXxxCtx methods are the context equivalents of GetXxx.
type DB struct {
	*sql.DB
	getChainVersionStmt    *sql.Stmt
	getChainMaxVersionStmt *sql.Stmt
	insertChainStmt        *sql.Stmt
	getTRCVersionStmt      *sql.Stmt
	getTRCMaxVersionStmt   *sql.Stmt
	insertTRCStmt          *sql.Stmt
}

func New(path string) (*DB, error) {
	var err error
	db := &DB{}
	if db.DB, err = sqlite.New(path, Schema, SchemaVersion); err != nil {
		return nil, err
	}

	// On future errors, close the sql database before exiting
	defer func() {
		if err != nil {
			db.Close()
		}
	}()
	if db.getChainVersionStmt, err = db.Prepare(getChainVersionStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getChainVersion", err)
	}
	if db.getChainMaxVersionStmt, err = db.Prepare(getChainMaxVersionStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getChainMaxVersion", err)
	}
	if db.insertChainStmt, err = db.Prepare(insertChainStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare insertChain", err)
	}
	if db.getTRCVersionStmt, err = db.Prepare(getTRCVersionStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getTRCVersion", err)
	}
	if db.getTRCMaxVersionStmt, err = db.Prepare(getTRCMaxVersionStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getTRCMaxVersion", err)
	}
	if db.insertTRCStmt, err = db.Prepare(insertTRCStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare insertTRC", err)
	}
	return db, nil
}

// GetChainVersion returns the specified version of the certificate chain for
// ia. If version is 0, this is equivalent to GetChainMaxVersion.
func (db *DB) GetChainVersion(ia addr.IA, version uint64) (*cert.Chain, error) {
	return db.GetChainVersionCtx(context.Background(), ia, version)
}

// GetChainVersionCtx is the context-aware version of GetChainVersion.
func (db *DB) GetChainVersionCtx(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Chain, error) {

	if version == 0 {
		return db.GetChainMaxVersionCtx(ctx, ia)
	}
	var raw common.RawBytes
	err := db.getChainVersionStmt.QueryRowContext(ctx, ia.I, ia.A, version).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, common.NewBasicError("Database access error", err)
	}
	chain, err := cert.ChainFromRaw(raw, false)
	if err != nil {
		return nil, common.NewBasicError("Chain parse error", err, "ia", ia, "version", version)
	}
	return chain, nil
}

func (db *DB) GetChainMaxVersion(ia addr.IA) (*cert.Chain, error) {
	return db.GetChainMaxVersionCtx(context.Background(), ia)
}

func (db *DB) GetChainMaxVersionCtx(ctx context.Context, ia addr.IA) (*cert.Chain, error) {
	var raw common.RawBytes
	err := db.getChainMaxVersionStmt.QueryRowContext(ctx, ia.I, ia.A).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, common.NewBasicError("Database access error", err)
	}
	chain, err := cert.ChainFromRaw(raw, false)
	if err != nil {
		return nil, common.NewBasicError("Chain parse error", err, "ia", ia, "version", "max")
	}
	return chain, nil
}

func (db *DB) InsertChain(ia addr.IA, version uint64, chain *cert.Chain) error {
	return db.InsertChainCtx(context.Background(), ia, version, chain)
}

func (db *DB) InsertChainCtx(ctx context.Context, ia addr.IA, version uint64,
	chain *cert.Chain) error {
	raw, err := chain.JSON(false)
	if err != nil {
		return common.NewBasicError("Unable to convert to JSON", err)
	}
	_, err = db.insertChainStmt.Exec(ia.I, ia.A, version, raw)
	return err
}

// GetTRCVersion returns the specified version of the TRC for
// isd. If version is 0, this is equivalent to GetTRCMaxVersion.
func (db *DB) GetTRCVersion(isd uint16, version uint64) (*trc.TRC, error) {
	return db.GetTRCVersionCtx(context.Background(), isd, version)
}

// GetTRCVersionCtx is the context aware version of GetTRCVersion.
func (db *DB) GetTRCVersionCtx(ctx context.Context, isd uint16, version uint64) (*trc.TRC, error) {
	if version == 0 {
		return db.GetTRCMaxVersionCtx(ctx, isd)
	}
	var raw common.RawBytes
	err := db.getTRCVersionStmt.QueryRowContext(ctx, isd, version).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, common.NewBasicError("Database access error", err)
	}
	trcobj, err := trc.TRCFromRaw(raw, false)
	if err != nil {
		return nil, common.NewBasicError("TRC parse error", err, "isd", isd)
	}
	return trcobj, nil
}

func (db *DB) GetTRCMaxVersion(isd uint16) (*trc.TRC, error) {
	return db.GetTRCMaxVersionCtx(context.Background(), isd)
}

func (db *DB) GetTRCMaxVersionCtx(ctx context.Context, isd uint16) (*trc.TRC, error) {
	var raw common.RawBytes
	err := db.getTRCMaxVersionStmt.QueryRowContext(ctx, isd).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, common.NewBasicError("Database access error", err)
	}
	trcobj, err := trc.TRCFromRaw(raw, false)
	if err != nil {
		return nil, common.NewBasicError("TRC parse error", err, "isd", isd, "version", "max")
	}
	return trcobj, nil
}

func (db *DB) InsertTRC(isd addr.ISD, version uint64, trcobj *trc.TRC) error {
	return db.InsertTRCCtx(context.Background(), isd, version, trcobj)
}

func (db *DB) InsertTRCCtx(ctx context.Context, isd addr.ISD, version uint64,
	trcobj *trc.TRC) error {

	raw, err := trcobj.JSON(false)
	if err != nil {
		return common.NewBasicError("Unable to convert to JSON", err)
	}
	_, err = db.insertTRCStmt.ExecContext(ctx, isd, version, raw)
	return err
}
