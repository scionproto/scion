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
package trustdbsqlite

import (
	"context"
	"database/sql"
	"sync"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/scrypto"
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
	getAllChainsStr = `
			SELECT cic.OrderKey, cic.Data AS IData, lc.Data AS LData FROM (
				SELECT * FROM Chains ch
				LEFT JOIN IssuerCerts ic ON ch.IssCertsRowID = ic.RowID) as cic
			INNER JOIN LeafCerts lc USING (IsdID, AsID, Version)
			ORDER BY cic.IsdID, cic.AsID, cic.Version, cic.OrderKey
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
	getAllTRCsStr = `
			SELECT Data FROM TRCs
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
	getAllChainsStmt          *sql.Stmt
	insertChainStmt           *sql.Stmt
	getTRCVersionStmt         *sql.Stmt
	getTRCMaxVersionStmt      *sql.Stmt
	insertTRCStmt             *sql.Stmt
	getAllTRCsStmt            *sql.Stmt
}

func New(path string) (trustdb.TrustDB, error) {
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
	if db.getAllChainsStmt, err = db.db.Prepare(getAllChainsStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getAllChains", err)
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
	if db.getAllTRCsStmt, err = db.db.Prepare(getAllTRCsStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getAllTRCs", err)
	}
	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.db.Close()
}

// GetIssCertVersion returns the specified version of the issuer certificate for
// ia. If version is scrypto.LatestVer, this is equivalent to GetIssCertMaxVersion.
func (db *DB) GetIssCertVersion(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Certificate, error) {

	if version == scrypto.LatestVer {
		return db.GetIssCertMaxVersion(ctx, ia)
	}
	db.RLock()
	defer db.RUnlock()
	var raw common.RawBytes
	err := db.getIssCertVersionStmt.QueryRowContext(ctx, ia.I, ia.A, version).Scan(&raw)
	return parseCert(raw, ia, version, err)
}

// GetIssCertMaxVersion returns the max version of the issuer certificate for ia.
func (db *DB) GetIssCertMaxVersion(ctx context.Context, ia addr.IA) (*cert.Certificate, error) {
	db.RLock()
	defer db.RUnlock()
	var raw common.RawBytes
	err := db.getIssCertMaxVersionStmt.QueryRowContext(ctx, ia.I, ia.A).Scan(&raw)
	return parseCert(raw, ia, scrypto.LatestVer, err)
}

// InsertIssCert inserts the issuer certificate.
func (db *DB) InsertIssCert(ctx context.Context, crt *cert.Certificate) (int64, error) {
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

// GetLeafCertVersion returns the specified version of the leaf certificate for
// ia. If version is scrypto.LatestVer, this is equivalent to GetLeafCertMaxVersion.
func (db *DB) GetLeafCertVersion(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Certificate, error) {

	if version == scrypto.LatestVer {
		return db.GetLeafCertMaxVersion(ctx, ia)
	}
	db.RLock()
	defer db.RUnlock()
	var raw common.RawBytes
	err := db.getLeafCertVersionStmt.QueryRowContext(ctx, ia.I, ia.A, version).Scan(&raw)
	return parseCert(raw, ia, version, err)
}

// GetLeafCertMaxVersion returns the max version of the leaf certificate for ia.
func (db *DB) GetLeafCertMaxVersion(ctx context.Context, ia addr.IA) (*cert.Certificate, error) {
	db.RLock()
	defer db.RUnlock()
	var raw common.RawBytes
	err := db.getLeafCertMaxVersionStmt.QueryRowContext(ctx, ia.I, ia.A).Scan(&raw)
	return parseCert(raw, ia, scrypto.LatestVer, err)
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
		if v == scrypto.LatestVer {
			return nil, common.NewBasicError("Cert parse error", err, "ia", ia, "version", "max")
		} else {
			return nil, common.NewBasicError("Cert parse error", err, "ia", ia, "version", v)
		}
	}
	return crt, nil
}

// InsertLeafCert inserts the leaf certificate.
func (db *DB) InsertLeafCert(ctx context.Context, crt *cert.Certificate) (int64, error) {
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
// ia. If version is scrypto.LatestVer, this is equivalent to GetChainMaxVersion.
func (db *DB) GetChainVersion(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Chain, error) {

	if version == scrypto.LatestVer {
		return db.GetChainMaxVersion(ctx, ia)
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

// GetChainMaxVersion returns the max version of the chain for ia.
func (db *DB) GetChainMaxVersion(ctx context.Context, ia addr.IA) (*cert.Chain, error) {
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

func (db *DB) GetAllChains(ctx context.Context) ([]*cert.Chain, error) {
	db.RLock()
	defer db.RUnlock()
	rows, err := db.getAllChainsStmt.QueryContext(ctx)
	if err != nil {
		return nil, common.NewBasicError("Database access error", err)
	}
	defer rows.Close()
	var chains []*cert.Chain
	var leafRaw common.RawBytes
	var issCertRaw common.RawBytes
	var orderKey int64
	var lastOrderKey int64 = 1
	currentCerts := make([]*cert.Certificate, 0, 2)
	for rows.Next() {
		err = rows.Scan(&orderKey, &issCertRaw, &leafRaw)
		if err != nil {
			return nil, err
		}
		// Wrap around means we start processing a new chain entry.
		if orderKey <= lastOrderKey {
			if len(currentCerts) > 0 {
				chain, err := cert.ChainFromSlice(currentCerts)
				if err != nil {
					return nil, err
				}
				chains = append(chains, chain)
				currentCerts = currentCerts[:0]
			}
			// While the leaf entry is in every result row,
			// it has to be the first entry in the chain we are building.
			crt, err := cert.CertificateFromRaw(leafRaw)
			if err != nil {
				return nil, err
			}
			currentCerts = append(currentCerts, crt)
		}
		crt, err := cert.CertificateFromRaw(issCertRaw)
		if err != nil {
			return nil, err
		}
		currentCerts = append(currentCerts, crt)
		lastOrderKey = orderKey
	}
	if len(currentCerts) > 0 {
		chain, err := cert.ChainFromSlice(currentCerts)
		if err != nil {
			return nil, err
		}
		chains = append(chains, chain)
	}
	return chains, nil
}

// InsertChain inserts chain into the database. The first return value is the
// number of rows affected.
func (db *DB) InsertChain(ctx context.Context, chain *cert.Chain) (int64, error) {
	if _, err := db.InsertLeafCert(ctx, chain.Leaf); err != nil {
		return 0, err
	}
	if _, err := db.InsertIssCert(ctx, chain.Issuer); err != nil {
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
// isd. If version is scrypto.LatestVer, this is equivalent to GetTRCMaxVersion.
func (db *DB) GetTRCVersion(ctx context.Context,
	isd addr.ISD, version uint64) (*trc.TRC, error) {

	if version == scrypto.LatestVer {
		return db.GetTRCMaxVersion(ctx, isd)
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

// GetTRCMaxVersion returns the max version of the TRC for ia.
func (db *DB) GetTRCMaxVersion(ctx context.Context, isd addr.ISD) (*trc.TRC, error) {
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
func (db *DB) InsertTRC(ctx context.Context, trcobj *trc.TRC) (int64, error) {
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

// GetAllTRCs fetches all TRCs from the database.
func (db *DB) GetAllTRCs(ctx context.Context) ([]*trc.TRC, error) {
	db.RLock()
	defer db.RUnlock()
	rows, err := db.getAllTRCsStmt.QueryContext(ctx)
	if err != nil {
		return nil, common.NewBasicError("Database access error", err)
	}
	defer rows.Close()
	var trcs []*trc.TRC
	var rawTRC common.RawBytes
	for rows.Next() {
		err = rows.Scan(&rawTRC)
		if err != nil {
			return nil, common.NewBasicError("Failed to scan rows", err)
		}
		trcobj, err := trc.TRCFromRaw(rawTRC, false)
		if err != nil {
			return nil, common.NewBasicError("TRC parse error", err)
		}
		trcs = append(trcs, trcobj)
	}
	return trcs, nil
}
