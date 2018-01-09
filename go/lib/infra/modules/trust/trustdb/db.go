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
	"github.com/scionproto/scion/go/lib/basedb"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
)

const (
	SchemaVersion = 1
	Schema        = ` CREATE TABLE TRCs (
		ISD INTEGER NOT NULL,
		Version INTEGER NOT NULL,
		Data TEXT NOT NULL,
		PRIMARY KEY (ISD, Version)
	);

	CREATE TABLE Chains (
		ISD INTEGER NOT NULL,
		ASN INTEGER NOT NULL,
		Version INTEGER NOT NULL,
		Data TEXT NOT NULL,
		PRIMARY KEY (ISD, ASN, Version)
	);
	`

	TRCsTable   = "TRCs"
	ChainsTable = "Chains"
)

var (
	queries = map[string]string{
		"getChainVersion": `
			SELECT Data FROM Chains
			WHERE ISD=? AND ASN=? AND Version=?
		`,
		"getChainMaxVersion": `
			SELECT Data FROM Chains
			WHERE ISD=? AND ASN=? AND Version=(SELECT Max(Version) FROM Chains)
		`,
		"insertChain": `
			INSERT INTO Chains (ISD, ASN, Version, Data) VALUES (?, ?, ?, ?)
		`,
		"getTRCVersion": `
			SELECT Data FROM TRCs
			WHERE ISD=? AND Version=?
		`,
		"getTRCMaxVersion": `
			SELECT Data FROM TRCs
			WHERE ISD=? AND Version=(SELECT Max(Version) FROM TRCs)
		`,
		"insertTRC": `
			INSERT INTO TRCs (ISD, Version, Data) VALUES (?, ?, ?)
		`,
	}
)

// DB is a database containing TRCs and Certificate Chains, stored in JSON format.
//
// DB currently stores unverified crypto objects.
//
// XXX(scrye): DB should contain only verified crypto objects, to prevent (1)
// DoS attempts that spam the service with fake objects that get stored, (2)
// repeated verifications of the same object, (3) poison attempts where a valid
// crypto object is overwritten with a bad one.
type DB struct {
	db                     *sql.DB
	getChainVersionStmt    *sql.Stmt
	getChainMaxVersionStmt *sql.Stmt
	insertChainStmt        *sql.Stmt
	getTRCVersionStmt      *sql.Stmt
	getTRCMaxVersionStmt   *sql.Stmt
	insertTRCStmt          *sql.Stmt
}

func New(path string) (*DB, error) {
	var err error
	var sqldb *sql.DB
	db := &DB{}
	if sqldb, err = basedb.New(path, Schema, SchemaVersion); err != nil {
		return nil, err
	}
	db.db = sqldb

	// On future errors, close the sql database before exiting
	defer func() {
		if err != nil {
			db.db.Close()
		}
	}()
	if db.getChainVersionStmt, err = sqldb.Prepare(queries["getChainVersion"]); err != nil {
		return nil, common.NewBasicError("Unable to prepare getChainVersion", err)
	}
	if db.getChainMaxVersionStmt, err = sqldb.Prepare(queries["getChainMaxVersion"]); err != nil {
		return nil, common.NewBasicError("Unable to prepare getChainMaxVersion", err, "err", err)
	}
	if db.insertChainStmt, err = sqldb.Prepare(queries["insertChain"]); err != nil {
		return nil, common.NewBasicError("Unable to prepare insertChain", err)
	}
	if db.getTRCVersionStmt, err = sqldb.Prepare(queries["getTRCVersion"]); err != nil {
		return nil, common.NewBasicError("Unable to prepare getTRCVersion", err)
	}
	if db.getTRCMaxVersionStmt, err = sqldb.Prepare(queries["getTRCMaxVersion"]); err != nil {
		return nil, common.NewBasicError("Unable to prepare getTRCMaxVersion", err)
	}
	if db.insertTRCStmt, err = sqldb.Prepare(queries["insertTRC"]); err != nil {
		return nil, common.NewBasicError("Unable to prepare insertTRC", err)
	}
	return db, nil
}

func (db *DB) GetChainVersionCtx(ctx context.Context, ia addr.ISD_AS, version uint64) (*cert.Chain, bool, error) {
	var raw common.RawBytes
	err := db.getChainVersionStmt.QueryRow(ia.I, ia.A, version).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	chain, err := cert.ChainFromRaw(raw, false)
	if err != nil {
		return nil, false, common.NewBasicError("Chain parse error", nil, "ia", ia, "version", version,
			"err", err)
	}
	return chain, true, nil
}

func (db *DB) GetChainMaxVersionCtx(ctx context.Context, ia addr.ISD_AS) (*cert.Chain, bool, error) {
	var raw common.RawBytes
	err := db.getChainMaxVersionStmt.QueryRow(ia.I, ia.A).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	chain, err := cert.ChainFromRaw(raw, false)
	if err != nil {
		return nil, false, common.NewBasicError("Chain parse error", nil, "ia", ia, "version", "max",
			"err", err)
	}
	return chain, true, nil
}

func (db *DB) InsertChainCtx(ctx context.Context, ia addr.ISD_AS, version uint64, chain *cert.Chain) error {
	raw, err := chain.JSON(false)
	if err != nil {
		return common.NewBasicError("Unable to convert to JSON", err)
	}
	_, err = db.insertChainStmt.Exec(ia.I, ia.A, version, raw)
	return err
}

func (db *DB) GetTRCVersionCtx(ctx context.Context, isd uint16, version uint64) (*trc.TRC, bool, error) {
	var raw common.RawBytes
	err := db.getTRCVersionStmt.QueryRow(isd, version).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	trcobj, err := trc.TRCFromRaw(raw, false)
	if err != nil {
		return nil, false, common.NewBasicError("TRC parse error", nil, "isd", isd, "err", err)
	}
	return trcobj, true, nil
}

func (db *DB) GetTRCMaxVersionCtx(ctx context.Context, isd uint16) (*trc.TRC, bool, error) {
	var raw common.RawBytes
	err := db.getTRCMaxVersionStmt.QueryRow(isd).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	trcobj, err := trc.TRCFromRaw(raw, false)
	if err != nil {
		return nil, false, common.NewBasicError("TRC parse error", nil, "isd", isd, "version", "max")
	}
	return trcobj, true, nil
}

func (db *DB) InsertTRCCtx(ctx context.Context, isd uint16, version uint64, trcobj *trc.TRC) error {
	raw, err := trcobj.JSON(false)
	if err != nil {
		return common.NewBasicError("Unable to convert to JSON", err)
	}
	_, err = db.insertTRCStmt.Exec(isd, version, raw)
	return err
}
