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

package sqlite

import (
	"context"
	"database/sql"
	"encoding/binary"
	"sync"
	"time"

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

func (x *executor) GetSegmentRsvFromID(ctx context.Context, ID *reservation.SegmentID) (
	*segment.Reservation, error) {

	const query = `SELECT rsv.inout_ingress,rsv.inout_egress,rsv.path,rsv.active_index,
		idx.index_number,idx.expiration,idx.state,idx.min_bw,idx.max_bw,idx.alloc_bw,idx.token
		FROM seg_reservation as rsv
		INNER JOIN seg_index AS idx ON rsv.row_id = idx.reservation
		WHERE rsv.id_as = $1 AND rsv.id_suffix = $2;`
	rows, err := x.db.QueryContext(ctx, query, ID.ASID, binary.BigEndian.Uint32(ID.Suffix[:]))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	indices := segment.Indices{}
	var ingressIFID, egressIFID common.IFIDType
	var activeIdx int
	var idx, expiration, state, minBW, maxBW, allocBW int32
	var path, token []byte
	if rows.Next() {
		if err := rows.Scan(&ingressIFID, &egressIFID, &path, &activeIdx,
			&idx, &expiration, &state, &minBW, &maxBW, &allocBW, &token); err != nil {
			return nil, err
		}
		tok, err := reservation.TokenFromRaw(token)
		if err != nil {
			return nil, db.NewDataError("invalid stored token", err)
		}
		index := segment.NewIndex(reservation.IndexNumber(idx),
			time.Unix(int64(expiration), 0), segment.IndexState(state), reservation.BWCls(minBW),
			reservation.BWCls(maxBW), reservation.BWCls(allocBW), tok)
		indices = append(indices, *index)
	}
	for rows.Next() {
		err := rows.Scan(nil, nil, nil,
			&idx, &expiration, &state, &minBW, &maxBW, &allocBW, &token)
		if err != nil {
			return nil, err
		}
	}
	// sort indices so they are consecutive modulo 16
	indices.Sort()
	// setup reservation
	rsv := segment.NewReservation()
	rsv.ID = *ID
	rsv.Ingress = ingressIFID
	rsv.Egress = egressIFID
	p, err := segment.NewPathFromRaw(path)
	if err != nil {
		return nil, err
	}
	rsv.Path = p
	rsv.Indices = indices
	if activeIdx != -1 {
		if err := rsv.SetIndexActive(reservation.IndexNumber(activeIdx)); err != nil {
			return nil, err
		}
	}
	return rsv, nil
}

// GetSegmentRsvFromSrcDstAS returns all reservations that start at src AS and end in dst AS.
func (x *executor) GetSegmentRsvFromSrcDstAS(ctx context.Context, srcIA, dstIA addr.IA) (
	[]*segment.Reservation, error) {

	x.Lock()
	defer x.Unlock()

	query := `SELECT r.reservation_id, r.ingress, r.egress
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
func (x *executor) SetSegmentActiveIndex(ctx context.Context, rsv *segment.Reservation,
	idx reservation.IndexNumber) error {

	return nil
}

// NewSegmentRsvIndex stores a new index for a segment reservation.
func (x *executor) NewSegmentIndex(ctx context.Context, rsv *segment.Reservation,
	idx reservation.IndexNumber, tok *reservation.Token) error {

	index, err := rsv.Index(idx)
	if err != nil {
		return db.NewInputDataError("invalid index number", err)
	}
	if tok == nil {
		return db.NewInputDataError("token argument is nil", nil)
	}
	index.Token = *tok
	return insertNewIndex(ctx, x.db, &rsv.ID, index)
}

// UpdateSegmentRsvIndex updates an index of a segment reservation.
func (x *executor) UpdateSegmentIndex(ctx context.Context, rsv *segment.Reservation,
	idx reservation.IndexNumber) error {

	return nil
}

// DeleteSegmentIndex removes the index from the DB. Used in cleanup.
func (x *executor) DeleteSegmentIndex(ctx context.Context, rsv *segment.Reservation,
	idx reservation.IndexNumber) error {

	return nil
}

// DeleteExpiredIndices will remove expired indices from the DB. If a reservation is left
// without any index after removing the expired ones, it will also be removed.
func (x *executor) DeleteExpiredIndices(ctx context.Context, now time.Time) (int, error) {
	return 0, nil
}

// DeleteSegmentRsv removes the segment reservation
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

func insertNewSegReservation(ctx context.Context, x db.Sqler, rsv *segment.Reservation,
	suffix uint32) error {

	const query = `INSERT INTO seg_reservation (id_as, id_suffix, ingress, egress,
		path, src_as, dst_as,active_index) VALUES ($1, $2, $3, $4, $5, $6, $7, -1)`
	_, err := x.ExecContext(ctx, query, rsv.Path.GetSrcIA().A, suffix,
		rsv.Ingress, rsv.Egress,
		rsv.Path.ToRaw(), rsv.Path.GetSrcIA().IAInt(), rsv.Path.GetDstIA().IAInt())
	return err
}

func insertNewIndex(ctx context.Context, x db.Sqler, segID *reservation.SegmentID,
	index *segment.Index) error {

	const query = `INSERT INTO seg_index (reservation,
		index_number,expiration,state,min_bw,max_bw,alloc_bw,token) VALUES (
		(SELECT row_id FROM seg_reservation WHERE id_as=$1 AND id_suffix=$2),
		$3,$4,$5,$6,$7,$8,$9)`
	suffix := binary.BigEndian.Uint32(segID.Suffix[:])
	_, err := x.ExecContext(ctx, query, segID.ASID, suffix, index.Idx, uint32(index.Expiration.Unix()),
		index.State(), index.MinBW, index.MaxBW, index.AllocBW, index.Token.ToRaw())
	return err
}
