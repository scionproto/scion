// Copyright 2020 ETH Zurich, Anapaya Systems
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

package reservationdbsqlite

import (
	"context"
	"database/sql"
	"encoding/binary"
	"sync"

	"github.com/mattn/go-sqlite3"
	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/cs/reservation/e2e"
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/cs/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/serrors"
)

type Backend struct {
	*executor
	db *sql.DB
}

var _ backend.DB = (*Backend)(nil)

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
func (b *Backend) BeginTransaction(ctx context.Context, opts *sql.TxOptions) (
	backend.Transaction, error) {

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

// Close closes the databse.
func (b *Backend) Close() error {
	return b.db.Close()
}

type transaction struct {
	*executor
	tx *sql.Tx
}

var _ backend.Transaction = (*transaction)(nil)

func (t *transaction) Commit() error {
	t.Lock()
	defer t.Unlock()
	return t.tx.Commit()
}

func (t *transaction) Rollback() error {
	t.Lock()
	defer t.Unlock()
	return t.tx.Rollback()
}

type executor struct {
	sync.RWMutex
	db db.Sqler
}

func (x *executor) GetSegmentRsvFromID(ctx context.Context, ID reservation.SegmentID,
	idx *reservation.IndexNumber) (*segment.Reservation, error) {

	return nil, nil
}

// GetSegmentRsvFromSrcDstAS returns all reservations that start at src AS and end in dst AS.
func (x *executor) GetSegmentRsvFromSrcDstAS(ctx context.Context, srcIA, dstIA addr.IA) (
	[]*segment.Reservation, error) {

	x.Lock()
	defer x.Unlock()

	query := `SELECT r.reservation_id, r.inout_ingress, r.inout_egress
	FROM seg_reservation r
	WHERE r.src_as = ?1 AND r.dst_as = ?2`
	rows, err := x.db.QueryContext(ctx, query, srcIA.IAInt(), dstIA.IAInt())
	if err != nil {
		return nil, db.NewReadError("error obtaining segment reservations", err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(); err != nil {
			return nil, db.NewReadError("error reading segment reservation", err)
		}
	}
	return nil, nil
}

// GetSegmentRsvFromPath searches for a segment reservation with the specified path.
func (x *executor) GetSegmentRsvFromPath(ctx context.Context, path *segment.Path) (
	*segment.Reservation, error) {

	return nil, nil
}

// GetSegmentRsvsFromIFPair returns all segment reservations that enter this AS at
// the specified ingress and exit at that egress.
func (x *executor) GetSegmentRsvsFromIFPair(ctx context.Context, ingress, egress common.IFIDType) (
	[]*segment.Reservation, error) {

	return nil, nil
}

func insertNewSegReservation(ctx context.Context, x db.Sqler, rsv *segment.Reservation,
	suffix uint32) error {
	const query = `INSERT INTO seg_reservation (id_as, id_suffix, inout_ingress ,inout_egress,
		path, src_as, dst_as) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := x.ExecContext(ctx, query, rsv.Path.GetSrcIA().A, suffix,
		rsv.IngressIFID, rsv.EgressIFID,
		rsv.Path.ToRaw(), rsv.Path.GetSrcIA().IAInt(), rsv.Path.GetDstIA().IAInt())
	return err
}

// NewSegmentRsv creates a new segment reservation in the DB, with an unused reservation ID.
// The created ID is set in the reservation pointer argument.
func (x *executor) NewSegmentRsv(ctx context.Context, rsv *segment.Reservation) error {
	var err error
	for retries := 0; retries < 3; retries++ {
		err = db.DoInTx(ctx, x.db, func(ctx context.Context, tx *sql.Tx) error {
			suffix, err := newSuffix(ctx, tx, rsv.ID.ASID)
			if err != nil {
				return err
			}
			if err := insertNewSegReservation(ctx, tx, rsv, suffix); err != nil {
				return err
			}
			binary.BigEndian.PutUint32(rsv.ID.Suffix[:], suffix)
			return nil
		})
		if err == nil {
			return nil
		}
		sqliteError, ok := err.(sqlite3.Error)
		if !ok || sqliteError.Code != sqlite3.ErrConstraint {
			return db.NewTxError("error inserting segment reservation", err)
		}
	}
	return db.NewTxError("error inserting segment reservation after 3 retries", err)
}

// SetActiveIndex updates the active index for the segment reservation.
func (x *executor) SetSegmentActiveIndex(ctx context.Context, rsv segment.Reservation,
	idx reservation.IndexNumber) error {

	return nil
}

// NewSegmentRsvIndex stores a new index for a segment reservation.
func (x *executor) NewSegmentIndex(ctx context.Context, rsv *segment.Reservation,
	idx reservation.IndexNumber) error {

	return nil
}

// UpdateSegmentRsvIndex updates an index of a segment reservation.
func (x *executor) UpdateSegmentIndex(ctx context.Context, rsv *segment.Reservation,
	idx reservation.IndexNumber) error {

	return nil
}

// DeleteExpiredIndices removes the index from the DB. Used in cleanup.
func (x *executor) DeleteSegmentIndex(ctx context.Context, rsv *segment.Reservation,
	idx reservation.IndexNumber) error {

	return nil
}

// DeleteExpiredIndices will remove expired indices from the DB. If a reservation is left
// without any index after removing the expired ones, it will also be removed.
func (x *executor) DeleteExpiredIndices(ctx context.Context) (int, error) {
	return 0, nil
}

// DeleteExpiredIndices removes the segment reservation
func (x *executor) DeleteSegmentRsv(ctx context.Context, ID reservation.SegmentID) error {
	return nil
}

// GetE2ERsvFromID finds the end to end resevation given its ID.
func (x *executor) GetE2ERsvFromID(ctx context.Context, ID reservation.E2EID,
	idx reservation.IndexNumber) (*e2e.Reservation, error) {

	return nil, nil
}

// NewE2EIndex stores a new index in the DB.
// If the e2e reservation does not exist, it is created.
func (x *executor) NewE2EIndex(ctx context.Context, rsv *e2e.Reservation,
	idx reservation.IndexNumber) error {

	return nil
}

// UpdateE2EIndex updates the token in an index of the e2e reservation.
func (x *executor) UpdateE2EIndex(ctx context.Context, rsv *e2e.Reservation,
	idx reservation.IndexNumber) error {

	return nil

}

// DeleteE2EIndex removes an e2e index. It is used in the cleanup process.
func (x *executor) DeleteE2EIndex(ctx context.Context, rsv *e2e.Reservation,
	idx reservation.IndexNumber) error {

	return nil
}

// newSuffix finds a segment reservation ID suffix not being used at the moment. Should be called
// inside a transaction so the suffix is not used in the meantime, or fail.
func newSuffix(ctx context.Context, x db.Sqler, ASID addr.AS) (uint32, error) {
	query := `SELECT MIN(id_suffix)+1 FROM (
		SELECT 0 AS id_suffix UNION ALL
		SELECT id_suffix FROM seg_reservation WHERE id_as = $1
		) WHERE id_suffix+1 NOT IN (SELECT id_suffix FROM seg_reservation WHERE id_as = $1);`
	var suffix uint32
	err := x.QueryRowContext(ctx, query, uint64(ASID)).Scan(&suffix)
	switch {
	case err == sql.ErrNoRows:
		return 0, serrors.New("unexpected error getting new suffix: no rows")
	case err != nil:
		return 0, serrors.WrapStr("unexpected error getting new suffix", err)
	}
	return suffix, nil
}
