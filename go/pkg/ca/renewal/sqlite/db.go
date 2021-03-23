// Copyright 2020 Anapaya Systems
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
	"crypto/x509"
	"database/sql"
	"sync"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/trust"
)

// DB implements the renewal DB with an SQLite backend.
type DB struct {
	db *sql.DB
	*executor
}

// New returns a new SQLite backend opening a database at the given path. If
// no database exists a new database is be created. If the schema version of the
// stored database is different from the one in schema.go, an error is returned.
func New(path string) (DB, error) {
	db, err := db.NewSqlite(path, Schema, SchemaVersion)
	if err != nil {
		return DB{}, err
	}
	return NewFromDB(db), nil
}

// NewFromDB returns a new backend from the given database.
func NewFromDB(db *sql.DB) DB {
	return DB{
		db: db,
		executor: &executor{
			db: db,
		},
	}
}

// SetMaxOpenConns sets the maximum number of open connections.
func (db DB) SetMaxOpenConns(maxOpenConns int) {
	db.db.SetMaxOpenConns(maxOpenConns)
}

// SetMaxIdleConns sets the maximum number of idle connections.
func (db DB) SetMaxIdleConns(maxIdleConns int) {
	db.db.SetMaxIdleConns(maxIdleConns)
}

// Close closes the database.
func (db DB) Close() error {
	return db.db.Close()
}

type executor struct {
	sync.RWMutex
	db db.Sqler
}

func (e *executor) InsertClientChain(ctx context.Context, chain []*x509.Certificate) (bool, error) {
	e.Lock()
	defer e.Unlock()

	if len(chain) != 2 {
		return false, serrors.WithCtx(db.ErrInvalidInputData, "msg", "invalid chain length",
			"expected", 2, "actual", len(chain))
	}
	ia, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		return false, serrors.Wrap(db.ErrInvalidInputData, err, "msg",
			"invalid AS cert, invalid ISD-AS")
	}
	query := `INSERT INTO client_chains (isd_id, as_id, serial_number, key_id,
								  not_before, not_after, as_cert, ca_cert)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	testQuery := `SELECT 1 FROM client_chains
				  WHERE serial_number=$1 AND as_cert=$2 AND ca_cert=$3`
	var inserted bool
	err = db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		r := tx.QueryRowContext(ctx, testQuery, chain[0].SerialNumber.Bytes(),
			chain[0].Raw, chain[1].Raw)
		var val int
		err := r.Scan(&val)
		if err == nil && val == 1 {
			return nil
		}
		q, err := tx.ExecContext(ctx, query, ia.I, ia.A, chain[0].SerialNumber.Bytes(),
			chain[0].SubjectKeyId, chain[0].NotBefore.UTC(), chain[0].NotAfter.UTC(),
			chain[0].Raw, chain[1].Raw)
		if err != nil {
			return serrors.Wrap(db.ErrWriteFailed, err)
		}
		ar, err := q.RowsAffected()
		if err != nil {
			return err
		}
		inserted = ar > 0
		return nil
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

func (e *executor) ClientChains(ctx context.Context,
	query trust.ChainQuery) ([][]*x509.Certificate, error) {

	e.RLock()
	defer e.RUnlock()

	sqlQuery := `SELECT as_cert, ca_cert FROM client_chains
				WHERE isd_id=$1 AND as_id=$2 AND key_id=$3 AND not_before<=$4 AND not_after>=$4`
	rows, err := e.db.QueryContext(ctx, sqlQuery, query.IA.I, query.IA.A,
		query.SubjectKeyID, query.Date.UTC())
	if err != nil {
		return nil, serrors.Wrap(db.ErrReadFailed, err)
	}
	defer rows.Close()
	var chains [][]*x509.Certificate
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, serrors.Wrap(db.ErrReadFailed, err)
		}
		var rawAS, rawCA []byte
		if err := rows.Scan(&rawAS, &rawCA); err != nil {
			return nil, serrors.Wrap(db.ErrReadFailed, err)
		}
		as, err := x509.ParseCertificate(rawAS)
		if err != nil {
			return nil, serrors.Wrap(db.ErrDataInvalid, err)
		}
		ca, err := x509.ParseCertificate(rawCA)
		if err != nil {
			return nil, serrors.Wrap(db.ErrDataInvalid, err)
		}
		chains = append(chains, []*x509.Certificate{as, ca})
	}
	return chains, nil
}
