// Copyright 2019 Anapaya Systems
//
// Licensed under the Apache License, version 2.0 (the "License");
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

package trustdbsqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/decoded"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

// Backend implements the trust DB with an SQLite backend.
type Backend struct {
	db *sql.DB
	*executor
}

// New returns a new SQLite backend opening a database at the given path. If
// no database exists a new database is be created. If the schema version of the
// stored database is different from the one in schema.go, an error is returned.
func New(path string) (*Backend, error) {
	db, err := db.NewSqlite(path, Schema, SchemaVersion)
	if err != nil {
		return nil, err
	}
	return &Backend{
		executor: &executor{
			db: db,
		},
		db: db,
	}, nil
}

// SetMaxOpenConns sets the maximum number of open connections.
func (b *Backend) SetMaxOpenConns(maxOpenConns int) {
	b.db.SetMaxOpenConns(maxOpenConns)
}

// SetMaxIdleConns sets the maximum number of idle connections.
func (b *Backend) SetMaxIdleConns(maxIdleConns int) {
	b.db.SetMaxIdleConns(maxIdleConns)
}

// BeginTransaction begins a transaction on the database.
func (b *Backend) BeginTransaction(ctx context.Context,
	opts *sql.TxOptions) (trust.Transaction, error) {

	b.Lock()
	defer b.Unlock()
	tx, err := b.db.BeginTx(ctx, opts)
	if err != nil {
		return nil, db.NewTxError("create tx", err)
	}
	return &transaction{
		executor: &executor{
			db: tx,
		},
		tx: tx,
	}, nil
}

// Close closes the database.
func (b *Backend) Close() error {
	return b.db.Close()
}

var _ (trust.Transaction) = (*transaction)(nil)

type transaction struct {
	*executor
	tx *sql.Tx
}

func (tx *transaction) Commit() error {
	tx.Lock()
	defer tx.Unlock()
	return tx.tx.Commit()
}

func (tx *transaction) Rollback() error {
	tx.Lock()
	defer tx.Unlock()
	return tx.tx.Rollback()
}

type executor struct {
	sync.RWMutex
	db db.Sqler
}

func (e *executor) TRCExists(ctx context.Context, d decoded.TRC) (bool, error) {
	e.RLock()
	defer e.RUnlock()
	return trcExists(ctx, e.db, d)
}

func (e *executor) GetTRC(ctx context.Context, id trust.TRCID) (*trc.TRC, error) {

	e.RLock()
	defer e.RUnlock()
	var pld []byte
	query := `SELECT pld FROM trcs WHERE isd_id=? AND version=?`
	if id.Version.IsLatest() {
		query = `SELECT pld FROM (SELECT pld, max(version) FROM trcs WHERE isd_id=?)
		         WHERE pld IS NOT NULL`
	}
	err := e.db.QueryRowContext(ctx, query, id.ISD, id.Version).Scan(&pld)
	switch {
	case err == sql.ErrNoRows:
		return nil, trust.ErrNotFound
	case err != nil:
		return nil, err
	}
	return trc.Encoded(pld).Decode()
}

func (e *executor) GetRawTRC(ctx context.Context, id trust.TRCID) ([]byte, error) {

	e.RLock()
	defer e.RUnlock()
	query := `SELECT raw FROM trcs WHERE isd_id=? AND version=?`
	if id.Version.IsLatest() {
		query = `SELECT raw FROM (SELECT raw, max(version) FROM trcs WHERE isd_id=?)
		         WHERE raw IS NOT NULL`
	}
	var raw []byte
	err := e.db.QueryRowContext(ctx, query, id.ISD, id.Version).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, trust.ErrNotFound
	}
	return raw, err
}

func (e *executor) GetTRCInfo(ctx context.Context, id trust.TRCID) (trust.TRCInfo, error) {
	e.RLock()
	defer e.RUnlock()
	query := `SELECT version, not_before, not_after, grace_period from trcs
	          WHERE isd_id=? AND version=?`
	if id.Version.IsLatest() {
		query = `SELECT max(version), not_before, not_after, grace_period from trcs WHERE isd_id=?`
	}
	var ver scrypto.Version
	var grace int
	var notBefore, notAfter uint32
	err := e.db.QueryRowContext(ctx, query, id.ISD, id.Version).
		Scan(&ver, &notBefore, &notAfter, &grace)
	switch {
	case err == sql.ErrNoRows:
		return trust.TRCInfo{}, trust.ErrNotFound
	case err != nil:
		return trust.TRCInfo{}, trust.ErrNotFound
	}
	info := trust.TRCInfo{
		Version: ver,
		Validity: scrypto.Validity{
			NotBefore: util.UnixTime{Time: util.SecsToTime(notBefore)},
			NotAfter:  util.UnixTime{Time: util.SecsToTime(notAfter)},
		},
		GracePeriod: time.Duration(grace) * time.Second,
	}
	return info, nil
}

func (e *executor) GetIssuingGrantKeyInfo(ctx context.Context, ia addr.IA,
	version scrypto.Version) (trust.KeyInfo, error) {

	// we chose the simple way to implement this, if this ever becomes a
	// performance bottleneck we can still add a separate table which contains
	// this information.
	t, err := e.GetTRC(ctx, trust.TRCID{ISD: ia.I, Version: version})
	if err != nil {
		return trust.KeyInfo{}, err
	}
	prim, ok := t.PrimaryASes[ia.A]
	if !ok {
		return trust.KeyInfo{}, trust.ErrNotFound
	}
	km, ok := prim.Keys[trc.IssuingGrantKey]
	if !ok {
		return trust.KeyInfo{}, trust.ErrNotFound
	}
	return trust.KeyInfo{
		TRC: trust.TRCInfo{
			Validity:    *t.Validity,
			GracePeriod: t.GracePeriod.Duration,
			Version:     t.Version,
		},
		Version: km.KeyVersion,
	}, nil
}

func (e *executor) InsertTRC(ctx context.Context, d decoded.TRC) (bool, error) {
	e.Lock()
	defer e.Unlock()

	h := hash([]byte(d.Signed.EncodedTRC))
	query := `INSERT INTO trcs (isd_id, version, raw, pld, pld_hash, not_before,
	          not_after, grace_period) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	var inserted bool
	err := db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		exists, err := trcExists(ctx, tx, d)
		switch {
		case err != nil:
			return err
		case exists:
			return nil
		}
		_, err = tx.ExecContext(ctx, query, d.TRC.ISD, d.TRC.Version, d.Raw,
			d.Signed.EncodedTRC, h, util.TimeToSecs(d.TRC.Validity.NotBefore.Time),
			util.TimeToSecs(d.TRC.Validity.NotAfter.Time),
			int(d.TRC.GracePeriod.Duration/time.Second))
		if err != nil {
			return err
		}
		inserted = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

func (e *executor) GetRawChain(ctx context.Context, id trust.ChainID) ([]byte, error) {

	e.RLock()
	defer e.RUnlock()
	query := `SELECT raw FROM chains WHERE isd_id=? AND as_id=? AND version=?`
	if id.Version.IsLatest() {
		query = `SELECT raw FROM (SELECT raw, max(version) FROM chains WHERE isd_id=? AND as_id=?)
		         WHERE raw IS NOT NULL`
	}
	var raw []byte
	err := e.db.QueryRowContext(ctx, query, id.IA.I, id.IA.A, id.Version).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, trust.ErrNotFound
	}
	return raw, err
}

func (e *executor) ChainExists(ctx context.Context, d decoded.Chain) (bool, error) {
	e.RLock()
	defer e.RUnlock()
	return chainExists(ctx, e.db, d)
}

func (e *executor) InsertChain(ctx context.Context, d decoded.Chain) (bool, bool, error) {
	e.Lock()
	defer e.Unlock()

	asHash, issHash := hash([]byte(d.Chain.AS.Encoded)), hash([]byte(d.Chain.Issuer.Encoded))
	var asInserted, issInserted bool
	err := db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		exists, err := chainExists(ctx, tx, d)
		switch {
		case err != nil:
			return err
		case exists:
			return nil
		}
		if issInserted, err = insertIssuer(ctx, tx, d.Issuer, d.Chain.Issuer); err != nil {
			return serrors.WrapStr("unable to insert issuer certificate", err)
		}
		query := `INSERT INTO chains (isd_id, as_id, version, raw, as_hash, issuer_hash)
		          VALUES ($1, $2, $3, $4, $5, $6)`
		_, err = tx.ExecContext(ctx, query, d.AS.Subject.I, d.AS.Subject.A, d.AS.Version,
			d.Raw, asHash, issHash)
		if err != nil {
			return err
		}
		asInserted = true
		return nil
	})
	if err != nil {
		return false, false, err
	}
	return asInserted, issInserted, nil
}

func insertIssuer(ctx context.Context, db db.Sqler, iss *cert.Issuer,
	signed cert.SignedIssuer) (bool, error) {

	query := `INSERT INTO issuer_certs (isd_id, as_id, version, pld, pld_hash, protected, signature)
	          VALUES ($1, $2, $3, $4, $5, $6, $7)`
	exists, err := issuerExists(ctx, db, iss, signed)
	switch {
	case err != nil:
		return false, err
	case exists:
		return false, nil
	}
	_, err = db.ExecContext(ctx, query, iss.Subject.I, iss.Subject.A, iss.Version, signed.Encoded,
		hash([]byte(signed.Encoded)), signed.EncodedProtected, signed.Signature)
	if err != nil {
		return false, err
	}
	return true, nil
}

func trcExists(ctx context.Context, db db.Sqler, d decoded.TRC) (bool, error) {
	var dbHash []byte
	query := `SELECT pld_hash FROM trcs WHERE isd_id=? AND version=?`
	err := db.QueryRowContext(ctx, query, d.TRC.ISD, d.TRC.Version).Scan(&dbHash)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	case !bytes.Equal(hash([]byte(d.Signed.EncodedTRC)), dbHash):
		return true, trust.ErrContentMismatch
	default:
		return true, nil
	}
}

func chainExists(ctx context.Context, db db.Sqler, d decoded.Chain) (bool, error) {
	var asHash, issHash []byte
	query := `SELECT as_hash, issuer_hash FROM chains WHERE isd_id=? AND as_id=? AND version=?`
	err := db.QueryRowContext(ctx, query, d.AS.Subject.I, d.AS.Subject.A, d.AS.Version).Scan(
		&asHash, &issHash)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	case !bytes.Equal(hash([]byte(d.Chain.AS.Encoded)), asHash):
		return false, serrors.WithCtx(trust.ErrContentMismatch, "part", "as")
	case !bytes.Equal(hash([]byte(d.Chain.Issuer.Encoded)), issHash):
		return false, serrors.WithCtx(trust.ErrContentMismatch, "part", "issuer")
	default:
		return true, nil
	}
}

func issuerExists(ctx context.Context, db db.Sqler, iss *cert.Issuer,
	signed cert.SignedIssuer) (bool, error) {

	var dbHash []byte
	query := `SELECT pld_hash FROM issuer_certs Where isd_id=? AND as_id=? AND version=?`
	err := db.QueryRowContext(ctx, query, iss.Subject.I, iss.Subject.A, iss.Version).Scan(&dbHash)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	case !bytes.Equal(hash([]byte(signed.Encoded)), dbHash):
		return false, trust.ErrContentMismatch
	default:
		return true, nil
	}
}

func hash(input []byte) []byte {
	h := sha256.Sum256(input)
	return h[:]
}
