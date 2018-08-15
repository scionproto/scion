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

// Package trustdb provides wrappers for SQL calls for managing a database
// containing TRCs and Certificate Chains.
//
// KNOWN ISSUE: DB methods serialize to/dezerialize from JSON on each call.
// For performance penalty details, check the benchmarks in the test file.
package trustdb

import (
	"context"
	"database/sql"
	"sync"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/sqlite"
)

const (
	Path          = "trustDB.sqlite3"
	SchemaVersion = 1
	Schema        = `
	CREATE TABLE TRCs (
		IsdID INTEGER NOT NULL,
		Version INTEGER NOT NULL,
		Data TEXT NOT NULL,
		PRIMARY KEY (IsdID, Version)
	);

	CREATE TABLE Chains (
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		Version INTEGER NOT NULL,
		OrderKey INTEGER NOT NULL,
		IssCertsRowID INTEGER NOT NULL,
		PRIMARY KEY (IsdID, AsID, Version, OrderKey)
		FOREIGN KEY (IssCertsRowID) REFERENCES IssuerCerts(RowID)
	);

	CREATE TABLE LeafCerts (
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		Version INTEGER NOT NULL,
		Data TEXT NOT NULL,
		PRIMARY KEY (IsdID, AsID, Version)
	);

	CREATE TABLE IssuerCerts (
		RowID INTEGER PRIMARY KEY AUTOINCREMENT,
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		Version INTEGER NOT NULL,
		Data TEXT NOT NULL,
		CONSTRAINT iav_unique UNIQUE (IsdID, AsID, Version)
	);
	`

	TRCsTable        = "TRCs"
	ChainsTable      = "Chains"
	IssuerCertsTable = "IssuerCerts"
	LeafCertsTable   = "LeafCerts"
)

const (
	getIssCertVersionStr = `
			SELECT Data FROM IssuerCerts WHERE IsdID=? AND AsID=? AND Version=?
		`
	getIssCertMaxVersionStr = `
			SELECT Data FROM (SELECT *, MAX(Version) FROM IssuerCerts WHERE IsdID=? AND AsID=?)
			WHERE Data IS NOT NULL
		`
	getIssCertRowIDStr = `
			SELECT RowID FROM IssuerCerts WHERE IsdID=? AND AsID=? AND Version=?
		`
	insertIssCertStr = `
			INSERT OR IGNORE INTO IssuerCerts (IsdID, AsID, Version, Data) VALUES (?, ?, ?, ?)
		`
	getLeafCertVersionStr = `
			SELECT Data FROM LeafCerts WHERE IsdID=? AND AsID=? AND Version=?
		`
	getLeafCertMaxVersionStr = `
			SELECT Data FROM (SELECT *, MAX(Version) FROM LeafCerts WHERE IsdID=? AND AsID=?)
			WHERE Data IS NOT NULL
		`
	insertLeafCertStr = `
			INSERT OR IGNORE INTO LeafCerts (IsdID, AsID, Version, Data) VALUES (?, ?, ?, ?)
		`
	getChainVersionStr = `
			SELECT Data, 0 FROM LeafCerts WHERE IsdID=? AND AsID=? AND Version=?
			UNION
			SELECT ic.Data, ch.OrderKey FROM IssuerCerts ic, Chains ch
			WHERE ic.RowID IN (
				SELECT IssCertsRowID FROM Chains WHERE IsdID=? AND AsID=? AND Version=?
			)
			ORDER BY ch.OrderKey
		`
	getChainMaxVersionStr = `
			SELECT Data, 0 FROM LeafCerts WHERE IsdID=? AND AsID=? AND Version=(
				SELECT MAX(Version) FROM Chains WHERE IsdID=? AND AsID=?
			)
			UNION
			SELECT ic.Data, ch.OrderKey FROM IssuerCerts ic, Chains ch
			WHERE ic.RowID IN (
				SELECT IssCertsRowID FROM Chains WHERE IsdID=? AND AsID=? AND Version=(
					SELECT MAX(Version) FROM Chains WHERE IsdID=? AND AsID=?
				)
			)
			ORDER BY ch.OrderKey
		`
	insertChainStr = `
			INSERT OR IGNORE INTO Chains (IsdID, AsID, Version, OrderKey, IssCertsRowID)
			VALUES (?, ?, ?, ?, ?)
		`
	getTRCVersionStr = `
			SELECT Data FROM TRCs WHERE IsdID=? AND Version=?
		`
	getTRCMaxVersionStr = `
			SELECT Data FROM (SELECT *, MAX(Version) FROM TRCs WHERE IsdID=?)
			WHERE Data IS NOT NULL
		`
	insertTRCStr = `
			INSERT OR IGNORE INTO TRCs (IsdID, Version, Data) VALUES (?, ?, ?)
		`
)

// DB is a database containing Certificates, Chains and TRCs, stored in JSON format.
//
// On errors, GetXxx methods return nil and the error. If no error occurred,
// but the database query yielded 0 results, the first returned value is nil.
// GetXxxCtx methods are the context equivalents of GetXxx.
type DB struct {
	sync.RWMutex
	db                        *sql.DB
	getIssCertVersionStmt     *sql.Stmt
	getIssCertMaxVersionStmt  *sql.Stmt
	getIssCertRowIDStmt       *sql.Stmt
	insertIssCertStmt         *sql.Stmt
	getLeafCertVersionStmt    *sql.Stmt
	getLeafCertMaxVersionStmt *sql.Stmt
	insertLeafCertStmt        *sql.Stmt
	getChainVersionStmt       *sql.Stmt
	getChainMaxVersionStmt    *sql.Stmt
	insertChainStmt           *sql.Stmt
	getTRCVersionStmt         *sql.Stmt
	getTRCMaxVersionStmt      *sql.Stmt
	insertTRCStmt             *sql.Stmt
}

func New(path string) (*DB, error) {
	var err error
	db := &DB{}
	if db.db, err = sqlite.New(path, Schema, SchemaVersion); err != nil {
		return nil, err
	}
	// On future errors, close the sql database before exiting
	defer func() {
		if err != nil {
			db.db.Close()
		}
	}()
	if db.getIssCertVersionStmt, err = db.db.Prepare(getIssCertVersionStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getIssCertVersion", err)
	}
	if db.getIssCertMaxVersionStmt, err = db.db.Prepare(getIssCertMaxVersionStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getIssCertMaxVersion", err)
	}
	if db.getIssCertRowIDStmt, err = db.db.Prepare(getIssCertRowIDStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getIssCertRowID", err)
	}
	if db.insertIssCertStmt, err = db.db.Prepare(insertIssCertStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare insertIssCert", err)
	}
	if db.getLeafCertVersionStmt, err = db.db.Prepare(getLeafCertVersionStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getLeafCertVersion", err)
	}
	if db.getLeafCertMaxVersionStmt, err = db.db.Prepare(getLeafCertMaxVersionStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getLeafCertMaxVersion", err)
	}
	if db.insertLeafCertStmt, err = db.db.Prepare(insertLeafCertStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare insertLeafCert", err)
	}
	if db.getChainVersionStmt, err = db.db.Prepare(getChainVersionStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getChainVersion", err)
	}
	if db.getChainMaxVersionStmt, err = db.db.Prepare(getChainMaxVersionStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getChainMaxVersion", err)
	}
	if db.insertChainStmt, err = db.db.Prepare(insertChainStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare insertChain", err)
	}
	if db.getTRCVersionStmt, err = db.db.Prepare(getTRCVersionStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getTRCVersion", err)
	}
	if db.getTRCMaxVersionStmt, err = db.db.Prepare(getTRCMaxVersionStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getTRCMaxVersion", err)
	}
	if db.insertTRCStmt, err = db.db.Prepare(insertTRCStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare insertTRC", err)
	}
	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.db.Close()
}

// GetIssCertVersion returns the specified version of the issuer certificate for
// ia. If version is 0, this is equivalent to GetCertMaxVersion.
func (db *DB) GetIssCertVersion(ia addr.IA, version uint64) (*cert.Certificate, error) {
	return db.GetIssCertVersionCtx(context.Background(), ia, version)
}

// GetIssCertVersionCtx is the context-aware version of GetIssCertVersion.
func (db *DB) GetIssCertVersionCtx(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Certificate, error) {

	if version == 0 {
		return db.GetIssCertMaxVersionCtx(ctx, ia)
	}
	db.RLock()
	defer db.RUnlock()
	var raw common.RawBytes
	err := db.getIssCertVersionStmt.QueryRowContext(ctx, ia.I, ia.A, version).Scan(&raw)
	return parseCert(raw, ia, version, err)
}

// GetIssCertMaxVersion returns the max version of the issuer certificate for ia.
func (db *DB) GetIssCertMaxVersion(ia addr.IA) (*cert.Certificate, error) {
	return db.GetIssCertMaxVersionCtx(context.Background(), ia)
}

// GetIssCertMaxVersionCtx is the context-aware version of GetIssCertMaxVersion.
func (db *DB) GetIssCertMaxVersionCtx(ctx context.Context, ia addr.IA) (*cert.Certificate, error) {
	db.RLock()
	defer db.RUnlock()
	var raw common.RawBytes
	err := db.getIssCertMaxVersionStmt.QueryRowContext(ctx, ia.I, ia.A).Scan(&raw)
	return parseCert(raw, ia, 0, err)
}

// InsertIssCert inserts the issuer certificate.
func (db *DB) InsertIssCert(c *cert.Certificate) (int64, error) {
	return db.InsertIssCertCtx(context.Background(), c)
}

func (db *DB) InsertIssCertCtx(ctx context.Context, crt *cert.Certificate) (int64, error) {
	raw, err := crt.JSON(false)
	if err != nil {
		return 0, common.NewBasicError("Unable to convert to JSON", err)
	}
	db.Lock()
	defer db.Unlock()
	res, err := db.insertIssCertStmt.ExecContext(ctx,
		crt.Subject.I, crt.Subject.A, crt.Version, raw)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GetLeafCertVersion returns the specified version of the issuer certificate for
// ia. If version is 0, this is equivalent to GetCertMaxVersion.
func (db *DB) GetLeafCertVersion(ia addr.IA, version uint64) (*cert.Certificate, error) {
	return db.GetLeafCertVersionCtx(context.Background(), ia, version)
}

// GetLeafCertVersionCtx is the context-aware version of GetLeafCertVersion.
func (db *DB) GetLeafCertVersionCtx(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Certificate, error) {

	if version == 0 {
		return db.GetLeafCertMaxVersionCtx(ctx, ia)
	}
	db.RLock()
	defer db.RUnlock()
	var raw common.RawBytes
	err := db.getLeafCertVersionStmt.QueryRowContext(ctx, ia.I, ia.A, version).Scan(&raw)
	return parseCert(raw, ia, version, err)
}

// GetLeafCertMaxVersion returns the max version of the issuer certificate for ia.
func (db *DB) GetLeafCertMaxVersion(ia addr.IA) (*cert.Certificate, error) {
	return db.GetLeafCertMaxVersionCtx(context.Background(), ia)
}

// GetLeafCertMaxVersionCtx is the context-aware version of GetLeafCertMaxVersion.
func (db *DB) GetLeafCertMaxVersionCtx(ctx context.Context, ia addr.IA) (*cert.Certificate, error) {
	db.RLock()
	defer db.RUnlock()
	var raw common.RawBytes
	err := db.getLeafCertMaxVersionStmt.QueryRowContext(ctx, ia.I, ia.A).Scan(&raw)
	return parseCert(raw, ia, 0, err)
}

func parseCert(raw common.RawBytes, ia addr.IA, v uint64, err error) (*cert.Certificate, error) {
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, common.NewBasicError("Database access error", err)
	}
	crt, err := cert.CertificateFromRaw(raw)
	if err != nil {
		if v == 0 {
			return nil, common.NewBasicError("Cert parse error", err, "ia", ia, "version", "max")
		} else {
			return nil, common.NewBasicError("Cert parse error", err, "ia", ia, "version", v)
		}
	}
	return crt, nil
}

// InsertLeafCert inserts the issuer certificate.
func (db *DB) InsertLeafCert(c *cert.Certificate) (int64, error) {
	return db.InsertLeafCertCtx(context.Background(), c)
}

func (db *DB) InsertLeafCertCtx(ctx context.Context, crt *cert.Certificate) (int64, error) {
	raw, err := crt.JSON(false)
	if err != nil {
		return 0, common.NewBasicError("Unable to convert to JSON", err)
	}
	db.Lock()
	defer db.Unlock()
	res, err := db.insertLeafCertStmt.ExecContext(ctx,
		crt.Subject.I, crt.Subject.A, crt.Version, raw)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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
	db.RLock()
	defer db.RUnlock()
	rows, err := db.getChainVersionStmt.QueryContext(ctx, ia.I, ia.A, version, ia.I, ia.A, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return parseChain(rows, err)
}

func (db *DB) GetChainMaxVersion(ia addr.IA) (*cert.Chain, error) {
	return db.GetChainMaxVersionCtx(context.Background(), ia)
}

func (db *DB) GetChainMaxVersionCtx(ctx context.Context, ia addr.IA) (*cert.Chain, error) {
	db.RLock()
	defer db.RUnlock()
	rows, err := db.getChainMaxVersionStmt.QueryContext(ctx, ia.I, ia.A, ia.I, ia.A, ia.I, ia.A,
		ia.I, ia.A)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return parseChain(rows, err)
}

func parseChain(rows *sql.Rows, err error) (*cert.Chain, error) {
	if err != nil {
		return nil, common.NewBasicError("Database access error", err)
	}
	certs := make([]*cert.Certificate, 0, 2)
	var raw common.RawBytes
	var pos int64
	for i := 0; rows.Next(); i++ {
		if err = rows.Scan(&raw, &pos); err != nil {
			return nil, err
		}
		crt, err := cert.CertificateFromRaw(raw)
		if err != nil {
			return nil, err
		}
		certs = append(certs, crt)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, nil
	}
	return cert.ChainFromSlice(certs)
}

// InsertChain inserts chain into the database. The first return value is the
// number of rows affected.
func (db *DB) InsertChain(chain *cert.Chain) (int64, error) {
	return db.InsertChainCtx(context.Background(), chain)
}

// InsertChainCtx is the context aware version of InsertChain.
func (db *DB) InsertChainCtx(ctx context.Context, chain *cert.Chain) (int64, error) {
	if _, err := db.InsertLeafCertCtx(ctx, chain.Leaf); err != nil {
		return 0, err
	}
	if _, err := db.InsertIssCertCtx(ctx, chain.Issuer); err != nil {
		return 0, err
	}
	db.Lock()
	defer db.Unlock()
	ia, ver := chain.IAVer()
	rowId, err := db.getIssCertRowIDCtx(ctx, chain.Issuer.Subject, chain.Issuer.Version)
	if err != nil {
		return 0, err
	}
	// NOTE(roosd): Adding multiple rows to Chains table has to be done in a transaction.
	res, err := db.insertChainStmt.ExecContext(ctx, ia.I, ia.A, ver, 1, rowId)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (db *DB) getIssCertRowIDCtx(ctx context.Context, ia addr.IA, ver uint64) (int64, error) {
	var rowId int64
	err := db.getIssCertRowIDStmt.QueryRowContext(ctx, ia.I, ia.A, ver).Scan(&rowId)
	if err == sql.ErrNoRows {
		return 0, common.NewBasicError("Unable to get RowID of issuer certificate", nil,
			"ia", ia, "ver", ver)
	}
	if err != nil {
		return 0, common.NewBasicError("Database access error", err)
	}
	return rowId, nil
}

// GetTRCVersion returns the specified version of the TRC for
// isd. If version is 0, this is equivalent to GetTRCMaxVersion.
func (db *DB) GetTRCVersion(isd addr.ISD, version uint64) (*trc.TRC, error) {
	return db.GetTRCVersionCtx(context.Background(), isd, version)
}

// GetTRCVersionCtx is the context aware version of GetTRCVersion.
func (db *DB) GetTRCVersionCtx(ctx context.Context,
	isd addr.ISD, version uint64) (*trc.TRC, error) {

	if version == 0 {
		return db.GetTRCMaxVersionCtx(ctx, isd)
	}
	db.RLock()
	defer db.RUnlock()
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

func (db *DB) GetTRCMaxVersion(isd addr.ISD) (*trc.TRC, error) {
	return db.GetTRCMaxVersionCtx(context.Background(), isd)
}

func (db *DB) GetTRCMaxVersionCtx(ctx context.Context, isd addr.ISD) (*trc.TRC, error) {
	db.RLock()
	defer db.RUnlock()
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

// InsertTRC inserts trcobj into the database. The first return value is the
// number of rows affected.
func (db *DB) InsertTRC(trcobj *trc.TRC) (int64, error) {
	return db.InsertTRCCtx(context.Background(), trcobj)
}

// InsertTRCCtx is the context aware version of InsertTRC.
func (db *DB) InsertTRCCtx(ctx context.Context, trcobj *trc.TRC) (int64, error) {
	raw, err := trcobj.JSON(false)
	if err != nil {
		return 0, common.NewBasicError("Unable to convert to JSON", err)
	}
	db.Lock()
	defer db.Unlock()
	res, err := db.insertTRCStmt.ExecContext(ctx, trcobj.ISD, trcobj.Version, raw)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
