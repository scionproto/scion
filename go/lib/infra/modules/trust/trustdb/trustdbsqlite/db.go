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

// Package trustdbsqlite implements the trustdb interface with a sqlite backed DB.
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
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
)

const (
	Path          = "trustDB.sqlite3"
	SchemaVersion = 2
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

	CREATE TABLE CustKeys (
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		Version INTEGER NOT NULL,
		Key DATA NOT NULL,
		PRIMARY KEY (IsdID, AsID)
	);

	CREATE TABLE CustKeysLog (
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		Version INTEGER NOT NULL,
		Key DATA NOT NULL,
		PRIMARY KEY (IsdID, AsID, Version)
	);
	`

	TRCsTable        = "TRCs"
	ChainsTable      = "Chains"
	IssuerCertsTable = "IssuerCerts"
	LeafCertsTable   = "LeafCerts"
	CustKeysTable    = "CustKeys"
	CustKeysLogTable = "CustKeysLog"
)

const (
	getIssCertVersionStr = `
			SELECT Data FROM IssuerCerts WHERE IsdID=? AND AsID=? AND Version=?
		`
	getIssCertMaxVersionStr = `
			SELECT Data FROM (SELECT *, MAX(Version) FROM IssuerCerts WHERE IsdID=? AND AsID=?)
			WHERE Data IS NOT NULL
		`
	getAllIssCertsStr = `
			SELECT Data, IsdID, AsID, Version FROM IssuerCerts
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
			SELECT Data, 0 FROM LeafCerts WHERE IsdID=?1 AND AsID=?2 AND Version=?3
			UNION
			SELECT ic.Data, ch.OrderKey FROM IssuerCerts ic, Chains ch
			WHERE ic.RowID IN (
				SELECT IssCertsRowID FROM Chains WHERE IsdID=?1 AND AsID=?2 AND Version=?3
			)
			ORDER BY ch.OrderKey
		`
	getChainMaxVersionStr = `
			SELECT Data, 0 FROM LeafCerts WHERE IsdID=?1 AND AsID=?2 AND Version=(
				SELECT MAX(Version) FROM Chains WHERE IsdID=?1 AND AsID=?2
			)
			UNION
			SELECT ic.Data, ch.OrderKey FROM IssuerCerts ic, Chains ch
			WHERE ic.RowID IN (
				SELECT IssCertsRowID FROM Chains WHERE IsdID=?1 AND AsID=?2 AND Version=(
					SELECT MAX(Version) FROM Chains WHERE IsdID=?1 AND AsID=?2
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
	getCustKeyStr = `
			SELECT Key, Version FROM CustKeys WHERE IsdID=? AND AsID=?
	`
	getAllCustKeyStr = `
			SELECT Key, IsdID, AsID, Version FROM CustKeys
	`
	insertCustKeyStr = `
			INSERT INTO CustKeys (IsdID, AsID, Version, Key) VALUES (?, ?, ?, ?)
	`

	insertCustKeyLogStr = `
			INSERT OR IGNORE INTO CustKeysLog (IsdID, AsID, Version, Key) VALUES (?, ?, ?, ?)
	`

	updateCustKeyStr = `
			UPDATE CustKeys SET Version = ?, Key = ? WHERE IsdID = ? AND AsID = ? AND Version = ? 
	`
)

type Backend struct {
	*executor
	db *sql.DB
}

func New(path string) (*Backend, error) {
	var err error
	tdb := &Backend{}
	tdb.executor = &executor{}
	if tdb.db, err = db.NewSqlite(path, Schema, SchemaVersion); err != nil {
		return nil, err
	}
	tdb.executor.db = tdb.db
	return tdb, nil
}

func (db *Backend) SetMaxOpenConns(maxOpenConns int) {
	db.db.SetMaxOpenConns(maxOpenConns)
}

func (db *Backend) SetMaxIdleConns(maxIdleConns int) {
	db.db.SetMaxIdleConns(maxIdleConns)
}

// Close closes the database connection.
func (db *Backend) Close() error {
	return db.db.Close()
}

// BeginTransaction starts a new transaction.
func (db *Backend) BeginTransaction(ctx context.Context,
	opts *sql.TxOptions) (trustdb.Transaction, error) {

	db.Lock()
	defer db.Unlock()
	tx, err := db.db.BeginTx(ctx, opts)
	if err != nil {
		return nil, common.NewBasicError("Failed to create transaction", err)
	}
	return &transaction{
		executor: &executor{
			db: tx,
		},
		tx: tx,
	}, nil
}

type executor struct {
	sync.RWMutex
	db db.Sqler
}

// GetIssCertVersion returns the specified version of the issuer certificate for
// ia. If version is scrypto.LatestVer, this is equivalent to GetIssCertMaxVersion.
func (db *executor) GetIssCertVersion(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Certificate, error) {

	if version == scrypto.LatestVer {
		return db.GetIssCertMaxVersion(ctx, ia)
	}
	db.RLock()
	defer db.RUnlock()
	var raw common.RawBytes
	err := db.db.QueryRowContext(ctx, getIssCertVersionStr, ia.I, ia.A, version).Scan(&raw)
	return parseCert(raw, ia, version, err)
}

// GetIssCertMaxVersion returns the max version of the issuer certificate for ia.
func (db *executor) GetIssCertMaxVersion(ctx context.Context,
	ia addr.IA) (*cert.Certificate, error) {

	db.RLock()
	defer db.RUnlock()
	var raw common.RawBytes
	err := db.db.QueryRowContext(ctx, getIssCertMaxVersionStr, ia.I, ia.A).Scan(&raw)
	return parseCert(raw, ia, scrypto.LatestVer, err)
}

func (db *executor) GetAllIssCerts(ctx context.Context) (<-chan trustdb.CertOrErr, error) {
	db.RLock()
	defer db.RUnlock()

	rows, err := db.db.QueryContext(ctx, getAllIssCertsStr)
	if err != nil {
		return nil, err
	}
	certChan := make(chan trustdb.CertOrErr)
	go func() {
		defer close(certChan)
		defer rows.Close()
		var raw common.RawBytes
		ia := addr.IA{}
		var v uint64
		for rows.Next() {
			err = rows.Scan(&raw, &ia.I, &ia.A, &v)
			crt, err := parseCert(raw, ia, v, err)
			if err != nil {
				certChan <- trustdb.CertOrErr{Err: err}
				return
			}
			certChan <- trustdb.CertOrErr{Cert: crt}
		}
	}()
	return certChan, nil
}

// InsertIssCert inserts the issuer certificate.
func (db *executor) InsertIssCert(ctx context.Context, crt *cert.Certificate) (int64, error) {
	db.Lock()
	defer db.Unlock()
	return insertIssCert(ctx, db.db, crt)
}

// GetLeafCertVersion returns the specified version of the leaf certificate for
// ia. If version is scrypto.LatestVer, this is equivalent to GetLeafCertMaxVersion.
func (db *executor) GetLeafCertVersion(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Certificate, error) {

	if version == scrypto.LatestVer {
		return db.GetLeafCertMaxVersion(ctx, ia)
	}
	db.RLock()
	defer db.RUnlock()
	var raw common.RawBytes
	err := db.db.QueryRowContext(ctx, getLeafCertVersionStr, ia.I, ia.A, version).Scan(&raw)
	return parseCert(raw, ia, version, err)
}

// GetLeafCertMaxVersion returns the max version of the leaf certificate for ia.
func (db *executor) GetLeafCertMaxVersion(ctx context.Context,
	ia addr.IA) (*cert.Certificate, error) {

	db.RLock()
	defer db.RUnlock()
	var raw common.RawBytes
	err := db.db.QueryRowContext(ctx, getLeafCertMaxVersionStr, ia.I, ia.A).Scan(&raw)
	return parseCert(raw, ia, scrypto.LatestVer, err)
}

// InsertLeafCert inserts the leaf certificate.
func (db *executor) InsertLeafCert(ctx context.Context, crt *cert.Certificate) (int64, error) {
	db.Lock()
	defer db.Unlock()
	return insertLeafCert(ctx, db.db, crt)
}

// GetChainVersion returns the specified version of the certificate chain for
// ia. If version is scrypto.LatestVer, this is equivalent to GetChainMaxVersion.
func (db *executor) GetChainVersion(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Chain, error) {

	if version == scrypto.LatestVer {
		return db.GetChainMaxVersion(ctx, ia)
	}
	db.RLock()
	defer db.RUnlock()
	rows, err := db.db.QueryContext(ctx, getChainVersionStr, ia.I, ia.A, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return parseChain(rows, err)
}

// GetChainMaxVersion returns the max version of the chain for ia.
func (db *executor) GetChainMaxVersion(ctx context.Context, ia addr.IA) (*cert.Chain, error) {
	db.RLock()
	defer db.RUnlock()
	rows, err := db.db.QueryContext(ctx, getChainMaxVersionStr, ia.I, ia.A)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return parseChain(rows, err)
}

func (db *executor) GetAllChains(ctx context.Context) (<-chan trustdb.ChainOrErr, error) {
	db.RLock()
	defer db.RUnlock()
	rows, err := db.db.QueryContext(ctx, getAllChainsStr)
	if err != nil {
		return nil, common.NewBasicError("Database access error", err)
	}
	chainChan := make(chan trustdb.ChainOrErr)
	go func() {
		defer close(chainChan)
		defer rows.Close()
		var leafRaw common.RawBytes
		var issCertRaw common.RawBytes
		var orderKey int64
		var lastOrderKey int64 = 1
		currentCerts := make([]*cert.Certificate, 0, 2)
		for rows.Next() {
			err = rows.Scan(&orderKey, &issCertRaw, &leafRaw)
			if err != nil {
				chainChan <- trustdb.ChainOrErr{Err: err}
				return
			}
			// Wrap around means we start processing a new chain entry.
			if orderKey <= lastOrderKey {
				if len(currentCerts) > 0 {
					chain, err := cert.ChainFromSlice(currentCerts)
					if err != nil {
						chainChan <- trustdb.ChainOrErr{Err: err}
						return
					}
					chainChan <- trustdb.ChainOrErr{Chain: chain}
					currentCerts = currentCerts[:0]
				}
				// While the leaf entry is in every result row,
				// it has to be the first entry in the chain we are building.
				crt, err := cert.CertificateFromRaw(leafRaw)
				if err != nil {
					chainChan <- trustdb.ChainOrErr{Err: err}
					return
				}
				currentCerts = append(currentCerts, crt)
			}
			crt, err := cert.CertificateFromRaw(issCertRaw)
			if err != nil {
				chainChan <- trustdb.ChainOrErr{Err: err}
				return
			}
			currentCerts = append(currentCerts, crt)
			lastOrderKey = orderKey
		}
		if len(currentCerts) > 0 {
			chain, err := cert.ChainFromSlice(currentCerts)
			if err != nil {
				chainChan <- trustdb.ChainOrErr{Err: err}
				return
			}
			chainChan <- trustdb.ChainOrErr{Chain: chain}
		}
	}()
	return chainChan, nil
}

// InsertChain inserts chain into the database. The first return value is the
// number of rows affected.
func (db *executor) InsertChain(ctx context.Context, chain *cert.Chain) (int64, error) {
	db.Lock()
	defer db.Unlock()
	if _, err := insertLeafCert(ctx, db.db, chain.Leaf); err != nil {
		return 0, err
	}
	if _, err := insertIssCert(ctx, db.db, chain.Issuer); err != nil {
		return 0, err
	}
	ia, ver := chain.IAVer()
	rowId, err := getIssCertRowIDCtx(ctx, db.db, chain.Issuer.Subject, chain.Issuer.Version)
	if err != nil {
		return 0, err
	}
	// NOTE(roosd): Adding multiple rows to Chains table has to be done in a transaction.
	res, err := db.db.ExecContext(ctx, insertChainStr, ia.I, ia.A, ver, 1, rowId)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GetTRCVersion returns the specified version of the TRC for
// isd. If version is scrypto.LatestVer, this is equivalent to GetTRCMaxVersion.
func (db *executor) GetTRCVersion(ctx context.Context,
	isd addr.ISD, version uint64) (*trc.TRC, error) {

	if version == scrypto.LatestVer {
		return db.GetTRCMaxVersion(ctx, isd)
	}
	db.RLock()
	defer db.RUnlock()
	var raw common.RawBytes
	err := db.db.QueryRowContext(ctx, getTRCVersionStr, isd, version).Scan(&raw)
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
func (db *executor) GetTRCMaxVersion(ctx context.Context, isd addr.ISD) (*trc.TRC, error) {
	db.RLock()
	defer db.RUnlock()
	var raw common.RawBytes
	err := db.db.QueryRowContext(ctx, getTRCMaxVersionStr, isd).Scan(&raw)
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
func (db *executor) InsertTRC(ctx context.Context, trcobj *trc.TRC) (int64, error) {
	raw, err := trcobj.JSON(false)
	if err != nil {
		return 0, common.NewBasicError("Unable to convert to JSON", err)
	}
	db.Lock()
	defer db.Unlock()
	res, err := db.db.ExecContext(ctx, insertTRCStr, trcobj.ISD, trcobj.Version, raw)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GetAllTRCs fetches all TRCs from the database.
func (db *executor) GetAllTRCs(ctx context.Context) (<-chan trustdb.TrcOrErr, error) {
	db.RLock()
	defer db.RUnlock()
	rows, err := db.db.QueryContext(ctx, getAllTRCsStr)
	if err != nil {
		return nil, common.NewBasicError("Database access error", err)
	}
	trcChan := make(chan trustdb.TrcOrErr)
	go func() {
		defer close(trcChan)
		defer rows.Close()
		var rawTRC common.RawBytes
		for rows.Next() {
			err = rows.Scan(&rawTRC)
			if err != nil {
				trcChan <- trustdb.TrcOrErr{Err: common.NewBasicError("Failed to scan rows", err)}
				return
			}
			trcobj, err := trc.TRCFromRaw(rawTRC, false)
			if err != nil {
				trcChan <- trustdb.TrcOrErr{Err: common.NewBasicError("TRC parse error", err)}
				return
			}
			trcChan <- trustdb.TrcOrErr{TRC: trcobj}
		}
	}()
	return trcChan, nil
}

// GetCustKey gets the latest signing key and version for the specified customer AS.
func (db *executor) GetCustKey(ctx context.Context, ia addr.IA) (*trustdb.CustKey, error) {
	db.RLock()
	defer db.RUnlock()
	var key common.RawBytes
	var version uint64
	err := db.db.QueryRowContext(ctx, getCustKeyStr, ia.I, ia.A).Scan(&key, &version)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, common.NewBasicError("Failed to look up cust key", err)
	}
	return &trustdb.CustKey{IA: ia, Key: key, Version: version}, nil
}

func (db *executor) GetAllCustKeys(ctx context.Context) (<-chan trustdb.CustKeyOrErr, error) {
	db.RLock()
	defer db.RUnlock()

	rows, err := db.db.QueryContext(ctx, getAllCustKeyStr)
	if err != nil {
		return nil, err
	}
	custKeyChan := make(chan trustdb.CustKeyOrErr)
	go func() {
		defer close(custKeyChan)
		defer rows.Close()
		for rows.Next() {
			custKey := trustdb.CustKey{}
			err := rows.Scan(&custKey.Key, &custKey.IA.I, &custKey.IA.A, &custKey.Version)
			if err != nil {
				custKeyChan <- trustdb.CustKeyOrErr{Err: err}
				return
			}
			custKeyChan <- trustdb.CustKeyOrErr{CustKey: &custKey}
		}
	}()
	return custKeyChan, nil
}

// InsertCustKey implements trustdb.InsertCustKey.
func (db *executor) InsertCustKey(ctx context.Context,
	key *trustdb.CustKey, oldVersion uint64) error {

	if key == nil {
		return common.NewBasicError("Inserting nil key not allowed", nil)
	}
	if key.Version == oldVersion {
		return common.NewBasicError("Same version as oldVersion not allowed",
			nil, "version", key.Version)
	}
	db.Lock()
	defer db.Unlock()
	if oldVersion == 0 {
		_, err := db.db.ExecContext(ctx, insertCustKeyStr, key.IA.I, key.IA.A, key.Version, key.Key)
		if err != nil {
			return common.NewBasicError("Failed to insert cust key", err,
				"ia", key.IA, "ver", key.Version)
		}
	} else {
		res, err := db.db.ExecContext(ctx, updateCustKeyStr,
			key.Version, key.Key, key.IA.I, key.IA.A, oldVersion)
		if err != nil {
			return common.NewBasicError("Failed to update cust key", err,
				"ia", key.IA, "ver", key.Version)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return common.NewBasicError("Unable to determine affected rows", err)
		}
		if n == 0 {
			return common.NewBasicError("Cust keys has been modified", nil, "ia", key.IA,
				"newVersion", key.Version, "oldVersion", oldVersion)
		}
	}
	// Insert in the log table.
	_, err := db.db.ExecContext(ctx, insertCustKeyLogStr, key.IA.I, key.IA.A, key.Version, key.Key)
	return err
}

type transaction struct {
	*executor
	tx *sql.Tx
}

func (db *transaction) Commit() error {
	db.Lock()
	defer db.Unlock()
	if db.tx == nil {
		return common.NewBasicError("Transaction already done", nil)
	}
	err := db.tx.Commit()
	if err != nil {
		return common.NewBasicError("Failed to commit transaction", err)
	}
	db.tx = nil
	return nil
}

func (db *transaction) Rollback() error {
	db.Lock()
	defer db.Unlock()
	if db.tx == nil {
		return common.NewBasicError("Transaction already done", nil)
	}
	err := db.tx.Rollback()
	db.tx = nil
	if err != nil {
		return common.NewBasicError("Failed to rollback transaction", err)
	}
	return nil
}

func insertIssCert(ctx context.Context, db db.Sqler, crt *cert.Certificate) (int64, error) {
	raw, err := crt.JSON(false)
	if err != nil {
		return 0, common.NewBasicError("Unable to convert to JSON", err)
	}
	res, err := db.ExecContext(ctx, insertIssCertStr,
		crt.Subject.I, crt.Subject.A, crt.Version, raw)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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

func insertLeafCert(ctx context.Context, db db.Sqler, crt *cert.Certificate) (int64, error) {
	raw, err := crt.JSON(false)
	if err != nil {
		return 0, common.NewBasicError("Unable to convert to JSON", err)
	}
	res, err := db.ExecContext(ctx, insertLeafCertStr,
		crt.Subject.I, crt.Subject.A, crt.Version, raw)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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

func getIssCertRowIDCtx(ctx context.Context, db db.Sqler,
	ia addr.IA, ver uint64) (int64, error) {

	var rowId int64
	err := db.QueryRowContext(ctx, getIssCertRowIDStr, ia.I, ia.A, ver).Scan(&rowId)
	if err == sql.ErrNoRows {
		return 0, common.NewBasicError("Unable to get RowID of issuer certificate", nil,
			"ia", ia, "ver", ver)
	}
	if err != nil {
		return 0, common.NewBasicError("Database access error", err)
	}
	return rowId, nil
}
