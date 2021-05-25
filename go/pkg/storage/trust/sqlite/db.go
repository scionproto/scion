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
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"fmt"
	"strings"
	"sync"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	truststorage "github.com/scionproto/scion/go/pkg/storage/trust"
	"github.com/scionproto/scion/go/pkg/trust"
)

// DB implements the trust DB with an SQLite backend.
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

func (e *executor) SignedTRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	e.RLock()
	defer e.RUnlock()

	if id.Base.IsLatest() != id.Serial.IsLatest() {
		return cppki.SignedTRC{}, serrors.New("unsupported TRC ID for query", "id", id)
	}

	sqlQuery := `SELECT trc FROM trcs WHERE isd_id=$1
				ORDER BY base DESC, serial DESC
				LIMIT 1`
	args := []interface{}{id.ISD}
	if !id.Base.IsLatest() {
		sqlQuery = `SELECT trc FROM trcs WHERE isd_id=$1 AND base=$2 AND serial=$3`
		args = append(args, id.Base, id.Serial)
	}
	r := e.db.QueryRowContext(ctx, sqlQuery, args...)
	var rawTRC []byte
	err := r.Scan(&rawTRC)
	if err == sql.ErrNoRows {
		return cppki.SignedTRC{}, nil
	}
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap(db.ErrReadFailed, err)
	}
	trc, err := cppki.DecodeSignedTRC(rawTRC)
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap(db.ErrDataInvalid, err)
	}
	return trc, nil
}

func (e *executor) InsertTRC(ctx context.Context, trc cppki.SignedTRC) (bool, error) {
	e.Lock()
	defer e.Unlock()

	sqlQuery := `INSERT INTO trcs (isd_id, base, serial, fingerprint, trc)
				 SELECT $1, $2, $3, $4, $5 WHERE NOT EXISTS (
					 SELECT 1 FROM trcs
					 WHERE isd_id=$1 AND base=$2 AND serial=$3 AND fingerprint=$4
				 )`
	var inserted bool
	err := db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		r, err := tx.ExecContext(ctx, sqlQuery,
			trc.TRC.ID.ISD,
			trc.TRC.ID.Base,
			trc.TRC.ID.Serial,
			trcFingerprint(trc),
			trc.Raw,
		)
		if err != nil {
			return serrors.Wrap(db.ErrWriteFailed, err)
		}
		ar, err := r.RowsAffected()
		if err != nil {
			return serrors.Wrap(db.ErrWriteFailed, err)
		}
		inserted = ar > 0
		return nil
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

func (e *executor) Chains(ctx context.Context,
	query trust.ChainQuery) ([][]*x509.Certificate, error) {

	e.RLock()
	defer e.RUnlock()

	sqlQuery := []string{"SELECT as_cert, ca_cert FROM chains"}
	var args []interface{}
	var filters []string

	if len(query.SubjectKeyID) != 0 {
		args = append(args, query.SubjectKeyID)
		filters = append(filters, fmt.Sprintf("key_id=$%d", len(args)))
	}
	if !query.Date.IsZero() {
		args = append(args, query.Date.UTC())
		filters = append(filters, fmt.Sprintf("not_before<=$%d AND not_after>=$%d",
			len(args), len(args)))
	}
	if query.IA.I != 0 {
		args = append(args, query.IA.I)
		filters = append(filters, fmt.Sprintf("isd_id=$%d", len(args)))
	}
	if query.IA.A != 0 {
		args = append(args, query.IA.A)
		filters = append(filters, fmt.Sprintf("as_id=$%d", len(args)))
	}
	if len(filters) != 0 {
		sqlQuery = append(sqlQuery, "WHERE")
	}
	sqlQuery = append(sqlQuery, strings.Join(filters, " AND "))
	rows, err := e.db.QueryContext(ctx, strings.Join(sqlQuery, "\n"), args...)
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

func (e *executor) Chain(ctx context.Context,
	chainID []byte) ([]*x509.Certificate, error) {

	e.RLock()
	defer e.RUnlock()
	sqlQuery := fmt.Sprintf("SELECT as_cert, ca_cert FROM chains WHERE chain_fingerprint=$1")
	r := e.db.QueryRowContext(ctx, sqlQuery, chainID)
	var chain []*x509.Certificate
	var rawAS, rawCA []byte
	if err := r.Scan(&rawAS, &rawCA); err != nil {
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
	chain = []*x509.Certificate{as, ca}
	return chain, nil
}

func (e *executor) InsertChain(ctx context.Context, chain []*x509.Certificate) (bool, error) {
	e.Lock()
	defer e.Unlock()

	if len(chain) != 2 {
		return false, serrors.WithCtx(db.ErrInvalidInputData, "msg", "invalid chain length",
			"expected", 2, "actual", len(chain))
	}
	ia, err := cppki.ExtractIA(chain[0].Subject)
	if err != nil {
		return false, serrors.Wrap(db.ErrInvalidInputData, err,
			"msg", "invalid AS cert, invalid ISD-AS")
	}
	query := `INSERT INTO chains (isd_id, as_id, key_id, not_before, not_after,
								  chain_fingerprint, as_cert, ca_cert)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			  ON CONFLICT DO NOTHING`
	var inserted bool
	err = db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		r, err := tx.ExecContext(ctx, query, ia.I, ia.A, chain[0].SubjectKeyId,
			chain[0].NotBefore.UTC(), chain[0].NotAfter.UTC(),
			truststorage.ChainID(chain), chain[0].Raw, chain[1].Raw)
		if err != nil {
			return serrors.Wrap(db.ErrWriteFailed, err)
		}
		ar, err := r.RowsAffected()
		if err != nil {
			return serrors.Wrap(db.ErrWriteFailed, err)
		}
		inserted = ar > 0
		return nil
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// SignedTRCs returns the TRC from each ISD in the trust database according to the query.
func (e *executor) SignedTRCs(ctx context.Context,
	query truststorage.TRCsQuery) (cppki.SignedTRCs, error) {
	e.RLock()
	defer e.RUnlock()
	sqlQuery := []string{"SELECT trc FROM trcs"}
	var args []interface{}
	if len(query.ISD) > 0 {
		subQ := make([]string, 0, len(query.ISD))
		for _, ISD := range query.ISD {
			subQ = append(subQ, fmt.Sprintf("isd_id=$%d", len(args)+1))
			args = append(args, uint16(ISD))
		}
		where := fmt.Sprintf("(%s)", strings.Join(subQ, " OR "))
		sqlQuery = append(sqlQuery, fmt.Sprintf("WHERE %s", where))
	}
	if query.Latest == true {
		sqlQuery = append(sqlQuery, fmt.Sprintf("GROUP BY isd_id ORDER BY base DESC, serial DESC"))
	}
	rows, err := e.db.QueryContext(ctx, strings.Join(sqlQuery, "\n"), args...)
	if err != nil {
		return nil, serrors.Wrap(db.ErrReadFailed, err)
	}
	defer rows.Close()
	var res cppki.SignedTRCs
	for rows.Next() {
		var rawTRC []byte
		err := rows.Scan(&rawTRC)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		curRes, err := cppki.DecodeSignedTRC(rawTRC)
		if err != nil {
			return nil, serrors.Wrap(db.ErrDataInvalid, err)
		}
		res = append(res, curRes)
	}
	return res, err
}

func trcFingerprint(trc cppki.SignedTRC) []byte {
	h := sha256.New()
	h.Write(trc.TRC.Raw)
	return h.Sum(nil)
}
