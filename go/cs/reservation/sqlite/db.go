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
	"encoding/hex"
	"fmt"
	"strings"
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

	params := []interface{}{
		ID.ASID,
		binary.BigEndian.Uint32(ID.Suffix[:]),
	}
	rsvs, err := getSegReservations(ctx, x.db, "WHERE id_as = ? AND id_suffix = ?", params)
	if err != nil {
		return nil, err
	}
	switch len(rsvs) {
	case 0:
		return nil, nil
	case 1:
		return rsvs[0], nil
	default:
		return nil, db.NewDataError("more than 1 segment reservation found for an ID", nil,
			"count", len(rsvs), "id.asid", ID.ASID, "id.suffix", hex.EncodeToString(ID.Suffix[:]))
	}
}

// GetSegmentRsvsFromSrcDstIA returns all reservations that start at src AS and end in dst AS.
func (x *executor) GetSegmentRsvsFromSrcDstIA(ctx context.Context, srcIA, dstIA addr.IA) (
	[]*segment.Reservation, error) {

	conditions := make([]string, 0, 2)
	params := make([]interface{}, 0, 2)
	if !srcIA.IsZero() {
		conditions = append(conditions, "src_ia = ?")
		params = append(params, srcIA.IAInt())
	}
	if !dstIA.IsZero() {
		conditions = append(conditions, "dst_ia = ?")
		params = append(params, dstIA.IAInt())
	}
	if len(conditions) == 0 {
		return nil, serrors.New("no src or dst ia provided")
	}
	condition := fmt.Sprintf("WHERE %s", strings.Join(conditions, " AND "))
	return getSegReservations(ctx, x.db, condition, params)
}

// GetSegmentRsvFromPath searches for a segment reservation with the specified path.
func (x *executor) GetSegmentRsvFromPath(ctx context.Context, path segment.Path) (
	*segment.Reservation, error) {

	rsvs, err := getSegReservations(ctx, x.db, "WHERE path = ?", []interface{}{path.ToRaw()})
	if err != nil {
		return nil, err
	}
	switch len(rsvs) {
	case 0:
		return nil, nil
	case 1:
		return rsvs[0], nil
	default:
		return nil, db.NewDataError("more than 1 segment reservation found for a path", nil,
			"path", path.String())
	}
}

// GetSegmentRsvsFromIFPair returns all segment reservations that enter this AS at
// the specified ingress and exit at that egress.
func (x *executor) GetSegmentRsvsFromIFPair(ctx context.Context, ingress, egress *common.IFIDType) (
	[]*segment.Reservation, error) {

	conditions := make([]string, 0, 2)
	params := make([]interface{}, 0, 2)
	if ingress != nil {
		conditions = append(conditions, "ingress = ?")
		params = append(params, *ingress)
	}
	if egress != nil {
		conditions = append(conditions, "egress = ?")
		params = append(params, *egress)
	}
	if len(conditions) == 0 {
		return nil, serrors.New("no ingress or egress provided")
	}
	condition := fmt.Sprintf("WHERE %s", strings.Join(conditions, " AND "))
	return getSegReservations(ctx, x.db, condition, params)
}

// NewSegmentRsv creates a new segment reservation in the DB, with an unused reservation ID.
// The reservation must contain at least one index.
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

func (x *executor) PersistSegmentRsv(ctx context.Context, rsv *segment.Reservation) error {
	err := db.DoInTx(ctx, x.db, func(ctx context.Context, tx *sql.Tx) error {
		err := deleteSegmentRsv(ctx, tx, &rsv.ID)
		if err != nil {
			return err
		}
		suffix := binary.BigEndian.Uint32(rsv.ID.Suffix[:])
		return insertNewSegReservation(ctx, tx, rsv, suffix)
	})
	if err != nil {
		return db.NewTxError("error persisting reservation", err)
	}
	return nil
}

// DeleteExpiredIndices will remove expired indices from the DB. If a reservation is left
// without any index after removing the expired ones, it will also be removed.
func (x *executor) DeleteExpiredIndices(ctx context.Context, now time.Time) (int, error) {
	return 0, nil
}

// DeleteSegmentRsv removes the segment reservation
func (x *executor) DeleteSegmentRsv(ctx context.Context, ID *reservation.SegmentID) error {
	return deleteSegmentRsv(ctx, x.db, ID)
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
	const query = `SELECT MIN(id_suffix)+1 FROM (
			SELECT 0 AS id_suffix UNION ALL
			SELECT id_suffix FROM seg_reservation WHERE id_as = $1
		) WHERE id_suffix+1 NOT IN (SELECT id_suffix FROM seg_reservation WHERE id_as = $1)`
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

	activeIndex := -1
	if rsv.ActiveIndex() != nil {
		activeIndex = int(rsv.ActiveIndex().Idx)
	}
	const query = `INSERT INTO seg_reservation (id_as, id_suffix, ingress, egress,
		path, end_props, traffic_split, src_ia, dst_ia,active_index)
		VALUES (?, ?,?,?,?,?,?,?,?,?)`
	res, err := x.ExecContext(ctx, query, rsv.ID.ASID, suffix,
		rsv.Ingress, rsv.Egress, rsv.Path.ToRaw(), rsv.PathEndProps, rsv.TrafficSplit,
		rsv.Path.GetSrcIA().IAInt(), rsv.Path.GetDstIA().IAInt(), activeIndex)
	if err != nil {
		return err
	}
	if len(rsv.Indices) > 0 {
		rsvRowID, err := res.LastInsertId()
		if err != nil {
			return db.NewTxError("cannot obtain last insertion row id", err)
		}
		const queryIndexTmpl = `INSERT INTO seg_index (reservation, index_number, expiration, state,
		min_bw, max_bw, alloc_bw, token) VALUES (?,?,?,?,?,?,?,?)`
		params := make([]interface{}, 0, 8*len(rsv.Indices))
		for _, index := range rsv.Indices {
			params = append(params, rsvRowID, index.Idx,
				uint32(index.Expiration.Unix()), index.State(), index.MinBW, index.MaxBW,
				index.AllocBW, index.Token.ToRaw())
		}
		q := queryIndexTmpl + strings.Repeat(",(?,?,?,?,?,?,?,?)", len(rsv.Indices)-1)
		_, err = x.ExecContext(ctx, q, params...)
		if err != nil {
			return err
		}
	}
	return nil
}

type rsvFields struct {
	RowID        int
	AsID         uint64
	Suffix       uint32
	Ingress      common.IFIDType
	Egress       common.IFIDType
	Path         []byte
	EndProps     int
	TrafficSplit int
	ActiveIndex  int
}

func getSegReservations(ctx context.Context, x db.Sqler, condition string, params []interface{}) (
	[]*segment.Reservation, error) {

	const queryTmpl = `SELECT row_id,id_as,id_suffix,ingress,egress,path,
		end_props,traffic_split,active_index
		FROM seg_reservation %s`
	query := fmt.Sprintf(queryTmpl, condition)

	rows, err := x.QueryContext(ctx, query, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	reservationFields := []*rsvFields{}
	for rows.Next() {
		var f rsvFields
		err := rows.Scan(&f.RowID, &f.AsID, &f.Suffix, &f.Ingress, &f.Egress, &f.Path,
			&f.EndProps, &f.TrafficSplit, &f.ActiveIndex)
		if err != nil {
			return nil, err
		}
		reservationFields = append(reservationFields, &f)
	}
	reservations := []*segment.Reservation{}
	for _, rf := range reservationFields {
		rsv, err := buildSegRsvFromFields(ctx, x, rf)
		if err != nil {
			return nil, err
		}
		reservations = append(reservations, rsv)
	}
	return reservations, nil
}

// builds a segment.Reservation in memory from the fields and indices.
func buildSegRsvFromFields(ctx context.Context, x db.Sqler, fields *rsvFields) (
	*segment.Reservation, error) {

	indices, err := getSegIndices(ctx, x, fields.RowID)
	if err != nil {
		return nil, err
	}
	rsv := segment.NewReservation()
	rsv.ID.ASID = addr.AS(fields.AsID)
	binary.BigEndian.PutUint32(rsv.ID.Suffix[:], fields.Suffix)
	rsv.Ingress = fields.Ingress
	rsv.Egress = fields.Egress
	p, err := segment.NewPathFromRaw(fields.Path)
	if err != nil {
		return nil, err
	}
	rsv.Path = p
	rsv.PathEndProps = reservation.PathEndProps(fields.EndProps)
	rsv.TrafficSplit = reservation.SplitCls(fields.TrafficSplit)
	rsv.Indices = *indices
	if fields.ActiveIndex != -1 {
		if err := rsv.SetIndexActive(reservation.IndexNumber(fields.ActiveIndex)); err != nil {
			return nil, err
		}
	}
	return rsv, nil
}

// the rowID argument is the reservation row ID the indices belong to.
func getSegIndices(ctx context.Context, x db.Sqler, rowID int) (*segment.Indices, error) {
	const query = `SELECT index_number,expiration,state,min_bw,max_bw,alloc_bw,token
		FROM seg_index WHERE reservation=?`
	rows, err := x.QueryContext(ctx, query, rowID)
	if err != nil {
		return nil, db.NewReadError("cannot list indices", err)
	}

	indices := segment.Indices{}
	var idx, expiration, state, minBW, maxBW, allocBW int32
	var token []byte
	for rows.Next() {
		err := rows.Scan(&idx, &expiration, &state, &minBW, &maxBW, &allocBW, &token)
		if err != nil {
			return nil, db.NewReadError("could not get index values", err)
		}
		tok, err := reservation.TokenFromRaw(token)
		if err != nil {
			return nil, db.NewReadError("invalid stored token", err)
		}
		index := segment.NewIndex(reservation.IndexNumber(idx),
			time.Unix(int64(expiration), 0), segment.IndexState(state), reservation.BWCls(minBW),
			reservation.BWCls(maxBW), reservation.BWCls(allocBW), tok)
		indices = append(indices, *index)
	}
	// sort indices so they are consecutive modulo 16
	indices.Sort()
	return &indices, nil
}

func deleteSegmentRsv(ctx context.Context, x db.Sqler, rsvID *reservation.SegmentID) error {
	const query = `DELETE FROM seg_reservation WHERE id_as = ? AND id_suffix = ?`
	suffix := binary.BigEndian.Uint32(rsvID.Suffix[:])
	_, err := x.ExecContext(ctx, query, rsvID.ASID, suffix)
	return err
}
