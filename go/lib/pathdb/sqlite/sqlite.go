// Copyright 2017 ETH Zurich
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

// This file contains an SQLite backend for the PathDB.

package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/proto"
)

type segMeta struct {
	RowID       int64
	SegID       common.RawBytes
	FullID      common.RawBytes
	LastUpdated time.Time
	Seg         *seg.PathSegment
}

var noInsertion = pathdb.InsertStats{}

var _ pathdb.PathDB = (*Backend)(nil)

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

func (b *Backend) Close() error {
	return b.db.Close()
}

func (b *Backend) SetMaxOpenConns(maxOpenConns int) {
	b.db.SetMaxOpenConns(maxOpenConns)
}
func (b *Backend) SetMaxIdleConns(maxIdleConns int) {
	b.db.SetMaxIdleConns(maxIdleConns)
}

func (b *Backend) BeginTransaction(ctx context.Context,
	opts *sql.TxOptions) (pathdb.Transaction, error) {

	b.Lock()
	defer b.Unlock()
	tx, err := b.db.BeginTx(ctx, opts)
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

var _ (pathdb.Transaction) = (*transaction)(nil)

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

var _ (pathdb.ReadWrite) = (*executor)(nil)

type executor struct {
	sync.RWMutex
	db db.Sqler
}

func (e *executor) Insert(ctx context.Context, segMeta *seg.Meta) (pathdb.InsertStats, error) {
	return e.InsertWithHPCfgIDs(ctx, segMeta, []*query.HPCfgID{&query.NullHpCfgID})
}

func (e *executor) InsertWithHPCfgIDs(ctx context.Context, segMeta *seg.Meta,
	hpCfgIDs []*query.HPCfgID) (pathdb.InsertStats, error) {

	e.Lock()
	defer e.Unlock()
	if e.db == nil {
		return noInsertion, serrors.New("No database open")
	}
	pseg := segMeta.Segment
	// Check if we already have a path segment.
	segID, err := pseg.ID()
	if err != nil {
		return noInsertion, err
	}
	newFullId, err := pseg.FullId()
	if err != nil {
		return noInsertion, err
	}
	newInfo, err := pseg.InfoF()
	if err != nil {
		return noInsertion, err
	}
	meta, err := e.get(ctx, segID)
	if err != nil {
		return noInsertion, err
	}
	if meta != nil {
		// Check if the new segment is more recent.
		curInfo, _ := meta.Seg.InfoF()
		if newInfo.Timestamp().After(curInfo.Timestamp()) {
			// Update existing path segment.
			meta.Seg = pseg
			meta.LastUpdated = time.Now()
			if err := e.updateExisting(ctx, meta, segMeta.Type, newFullId, hpCfgIDs); err != nil {
				return noInsertion, err
			}
			return pathdb.InsertStats{Updated: 1}, nil
		}
		return noInsertion, nil
	}
	// Do full insert.
	err = db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		return insertFull(ctx, tx, segMeta, hpCfgIDs)
	})
	if err != nil {
		return noInsertion, err
	}
	return pathdb.InsertStats{Inserted: 1}, nil
}

func (e *executor) get(ctx context.Context, segID common.RawBytes) (*segMeta, error) {
	query := "SELECT RowID, SegID, FullID, LastUpdated, Segment FROM Segments WHERE SegID=?"
	var meta segMeta
	var lastUpdated int64
	var rawSeg common.RawBytes
	err := e.db.QueryRowContext(ctx, query, segID).Scan(
		&meta.RowID, &meta.SegID, &meta.FullID, &lastUpdated, &rawSeg)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, common.NewBasicError("Failed to lookup segment", err)
	}
	meta.LastUpdated = time.Unix(0, lastUpdated)
	meta.Seg, err = seg.NewSegFromRaw(rawSeg)
	if err != nil {
		return nil, err
	}
	return &meta, nil
}

func (e *executor) updateExisting(ctx context.Context, meta *segMeta,
	segType proto.PathSegType, newFullId common.RawBytes, hpCfgIDs []*query.HPCfgID) error {

	return db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {

		// Update segment.
		if err := updateSeg(ctx, tx, meta); err != nil {
			return err
		}
		// Make sure the existing segment is registered as the given type.
		if err := insertType(ctx, tx, meta.RowID, segType); err != nil {
			return err
		}
		// Check if the existing segment is registered with the given hpCfgIDs.
		for _, hpCfgID := range hpCfgIDs {
			if err := insertHPCfgID(ctx, tx, meta.RowID, hpCfgID); err != nil {
				return err
			}
		}
		// Update the IntfToSeg table
		if !bytes.Equal(newFullId, meta.FullID) {
			// Delete all old interfaces and then insert the new ones.
			// Calculating the actual diffset would be better, but this is way easier to implement.
			_, err := tx.ExecContext(ctx, `DELETE FROM IntfToSeg WHERE SegRowID=?`, meta.RowID)
			if err != nil {
				return err
			}
			if err := insertInterfaces(ctx, tx, meta.Seg.ASEntries, meta.RowID); err != nil {
				return err
			}
		}
		return nil
	})
}

func updateSeg(ctx context.Context, tx *sql.Tx, meta *segMeta) error {
	packedSeg, err := meta.Seg.Pack()
	if err != nil {
		return err
	}
	info, err := meta.Seg.InfoF()
	if err != nil {
		return err
	}
	exp := meta.Seg.MaxExpiry().Unix()
	fullID, err := meta.Seg.FullId()
	if err != nil {
		return err
	}
	stmtStr := `UPDATE Segments SET FullID=?, LastUpdated=?, InfoTs=?, Segment=?, MaxExpiry=?
				WHERE RowID=?`
	_, err = tx.ExecContext(ctx, stmtStr,
		fullID, meta.LastUpdated.UnixNano(), info.Timestamp(), packedSeg, exp, meta.RowID)
	if err != nil {
		return common.NewBasicError("Failed to update segment", err)
	}
	return nil
}

func insertType(ctx context.Context, tx *sql.Tx, segRowID int64,
	segType proto.PathSegType) error {

	_, err := tx.ExecContext(ctx, "INSERT INTO SegTypes (SegRowID, Type) VALUES (?, ?)",
		segRowID, segType)
	if err != nil {
		return common.NewBasicError("Failed to insert type", err)
	}
	return nil
}

func insertHPCfgID(ctx context.Context, tx *sql.Tx, segRowID int64,
	hpCfgID *query.HPCfgID) error {

	_, err := tx.ExecContext(ctx,
		"INSERT INTO HpCfgIds (SegRowID, IsdID, AsID, CfgID) VALUES (?, ?, ?, ?)",
		segRowID, hpCfgID.IA.I, hpCfgID.IA.A, hpCfgID.ID)
	if err != nil {
		return common.NewBasicError("Failed to insert hpCfgID", err)
	}
	return nil
}

func insertFull(ctx context.Context, tx *sql.Tx, segMeta *seg.Meta,
	hpCfgIDs []*query.HPCfgID) error {

	pseg := segMeta.Segment
	segID, err := pseg.ID()
	if err != nil {
		return err
	}
	fullID, err := pseg.FullId()
	if err != nil {
		return err
	}
	packedSeg, err := pseg.Pack()
	if err != nil {
		return err
	}
	info, err := pseg.InfoF()
	if err != nil {
		return err
	}
	st := pseg.FirstIA()
	end := pseg.LastIA()
	exp := pseg.MaxExpiry().Unix()
	// Insert path segment.
	inst := `INSERT INTO Segments (SegID, FullID, LastUpdated, InfoTs, Segment, MaxExpiry,
			StartIsdID, StartAsID, EndIsdID, EndAsID)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	res, err := tx.ExecContext(ctx, inst, segID, fullID, time.Now().UnixNano(),
		info.Timestamp().UnixNano(), packedSeg, exp, st.I, st.A, end.I, end.A)
	if err != nil {
		return common.NewBasicError("Failed to insert path segment", err)
	}
	segRowID, err := res.LastInsertId()
	if err != nil {
		return common.NewBasicError("Failed to retrieve segRowID of inserted segment", err)
	}
	// Insert all interfaces.
	if err = insertInterfaces(ctx, tx, pseg.ASEntries, segRowID); err != nil {
		return err
	}
	// Insert segType information.
	if err = insertType(ctx, tx, segRowID, segMeta.Type); err != nil {
		return err
	}
	// Insert hpCfgID information.
	for _, hpCfgID := range hpCfgIDs {
		if err = insertHPCfgID(ctx, tx, segRowID, hpCfgID); err != nil {
			return err
		}
	}
	return nil
}

func insertInterfaces(ctx context.Context, tx *sql.Tx,
	ases []*seg.ASEntry, segRowID int64) error {

	stmtStr := `INSERT INTO IntfToSeg (IsdID, AsID, IntfID, SegRowID) VALUES (?, ?, ?, ?)`
	stmt, err := tx.PrepareContext(ctx, stmtStr)
	if err != nil {
		return common.NewBasicError("Failed to prepare insert into IntfToSeg", err)
	}
	defer stmt.Close()
	for _, as := range ases {
		ia := as.IA()
		for idx, hop := range as.HopEntries {
			hof, err := hop.HopField()
			if err != nil {
				return common.NewBasicError("Failed to extract hop field", err)
			}
			if hof.ConsIngress != 0 {
				_, err = stmt.ExecContext(ctx, ia.I, ia.A, hof.ConsIngress, segRowID)
				if err != nil {
					return common.NewBasicError("Failed to insert Ingress into IntfToSeg", err)
				}
			}
			// Only insert the Egress interface for the first hop entry in an AS entry.
			if idx == 0 && hof.ConsEgress != 0 {
				_, err := stmt.ExecContext(ctx, ia.I, ia.A, hof.ConsEgress, segRowID)
				if err != nil {
					return common.NewBasicError("Failed to insert Egress into IntfToSeg", err)
				}
			}
		}
	}
	return nil
}

func (e *executor) Delete(ctx context.Context, params *query.Params) (int, error) {
	q, args := e.buildQuery(params)
	query := fmt.Sprintf("DELETE FROM Segments WHERE RowId IN(SELECT RowID FROM (%s))", q)
	return e.deleteInTx(ctx, func(tx *sql.Tx) (sql.Result, error) {
		return tx.ExecContext(ctx, query, args...)
	})
}

func (e *executor) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	return e.deleteInTx(ctx, func(tx *sql.Tx) (sql.Result, error) {
		delStmt := `DELETE FROM Segments WHERE MaxExpiry < ?`
		return tx.ExecContext(ctx, delStmt, now.Unix())
	})
}

func (e *executor) deleteInTx(ctx context.Context,
	delFunc func(tx *sql.Tx) (sql.Result, error)) (int, error) {

	e.Lock()
	defer e.Unlock()
	if e.db == nil {
		return 0, serrors.New("No database open")
	}
	return db.DeleteInTx(ctx, e.db, delFunc)
}

func (e *executor) Get(ctx context.Context, params *query.Params) (query.Results, error) {
	e.RLock()
	defer e.RUnlock()
	if e.db == nil {
		return nil, serrors.New("No database open")
	}
	stmt, args := e.buildQuery(params)
	rows, err := e.db.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, common.NewBasicError("Error looking up path segment", err, "q", stmt)
	}
	defer rows.Close()
	var res query.Results
	prevID := -1
	var curRes *query.Result
	for rows.Next() {
		var segRowID int
		var rawSeg sql.RawBytes
		var lastUpdated int64
		var segType proto.PathSegType
		hpCfgID := &query.HPCfgID{IA: addr.IA{}}
		err = rows.Scan(&segRowID, &rawSeg, &lastUpdated, &hpCfgID.IA.I,
			&hpCfgID.IA.A, &hpCfgID.ID, &segType)
		if err != nil {
			return nil, common.NewBasicError("Error reading DB response", err)
		}
		// Check if we have a new segment.
		if segRowID != prevID {
			if curRes != nil {
				res = append(res, curRes)
			}
			curRes = &query.Result{
				LastUpdate: time.Unix(0, lastUpdated),
				Type:       segType,
			}
			var err error
			curRes.Seg, err = seg.NewSegFromRaw(common.RawBytes(rawSeg))
			if err != nil {
				return nil, common.NewBasicError("Error unmarshalling segment", err)
			}
		}
		// Append hpCfgID to result
		curRes.HpCfgIDs = append(curRes.HpCfgIDs, hpCfgID)
		prevID = segRowID
	}
	if curRes != nil {
		res = append(res, curRes)
	}
	return res, nil
}

func (e *executor) buildQuery(params *query.Params) (string, []interface{}) {
	var args []interface{}
	query := []string{
		"SELECT DISTINCT s.RowID, s.Segment, s.LastUpdated," +
			" h.IsdID, h.AsID, h.CfgID, t.Type FROM Segments s",
		"JOIN HpCfgIds h ON h.SegRowID=s.RowID",
		"JOIN SegTypes t ON t.SegRowID=s.RowID",
	}
	if params == nil {
		return strings.Join(query, "\n"), args
	}
	joins := []string{}
	where := []string{}
	if len(params.SegIDs) > 0 {
		subQ := make([]string, 0, len(params.SegIDs))
		for _, segID := range params.SegIDs {
			subQ = append(subQ, "s.SegID=?")
			args = append(args, segID)
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if len(params.SegTypes) > 0 {
		subQ := []string{}
		for _, segType := range params.SegTypes {
			subQ = append(subQ, "t.Type=?")
			args = append(args, segType)
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if len(params.HpCfgIDs) > 0 {
		subQ := []string{}
		for _, hpCfgID := range params.HpCfgIDs {
			subQ = append(subQ, "(h.IsdID=? AND h.AsID=? AND h.CfgID=?)")
			args = append(args, hpCfgID.IA.I, hpCfgID.IA.A, hpCfgID.ID)
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if len(params.Intfs) > 0 {
		joins = append(joins, "JOIN IntfToSeg i ON i.SegRowID=s.RowID")
		subQ := []string{}
		for _, spec := range params.Intfs {
			subQ = append(subQ, "(i.IsdID=? AND i.AsID=? AND i.IntfID=?)")
			args = append(args, spec.IA.I, spec.IA.A, spec.IfID)
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if len(params.StartsAt) > 0 {
		subQ := []string{}
		for _, as := range params.StartsAt {
			if as.A == 0 {
				subQ = append(subQ, "(s.StartIsdID=?)")
				args = append(args, as.I)
			} else {
				subQ = append(subQ, "(s.StartIsdID=? AND s.StartAsID=?)")
				args = append(args, as.I, as.A)
			}
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if len(params.EndsAt) > 0 {
		subQ := []string{}
		for _, as := range params.EndsAt {
			if as.A == 0 {
				subQ = append(subQ, "(s.EndIsdID=?)")
				args = append(args, as.I)
			} else {
				subQ = append(subQ, "(s.EndIsdID=? AND s.EndAsID=?)")
				args = append(args, as.I, as.A)
			}
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if params.MinLastUpdate != nil {
		where = append(where, "(s.LastUpdated>?)")
		args = append(args, params.MinLastUpdate.UnixNano())
	}
	// Assemble the query.
	if len(joins) > 0 {
		query = append(query, strings.Join(joins, "\n"))
	}
	if len(where) > 0 {
		query = append(query, fmt.Sprintf("WHERE %s", strings.Join(where, " AND\n")))
	}
	query = append(query, " ORDER BY s.LastUpdated")
	return strings.Join(query, "\n"), args
}

func (e *executor) GetAll(ctx context.Context) (<-chan query.ResultOrErr, error) {
	e.RLock()
	defer e.RUnlock()
	if e.db == nil {
		return nil, serrors.New("No database open")
	}
	stmt, args := e.buildQuery(nil)
	rows, err := e.db.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, common.NewBasicError("Error looking up path segment", err, "q", stmt)
	}
	resCh := make(chan query.ResultOrErr)
	go func() {
		defer log.HandlePanic()
		defer close(resCh)
		defer rows.Close()
		prevID := -1
		var curRes *query.Result
		for rows.Next() {
			var segRowID int
			var rawSeg sql.RawBytes
			var lastUpdated int64
			var segType proto.PathSegType
			hpCfgID := &query.HPCfgID{IA: addr.IA{}}
			err = rows.Scan(&segRowID, &rawSeg, &lastUpdated,
				&hpCfgID.IA.I, &hpCfgID.IA.A, &hpCfgID.ID, &segType)
			if err != nil {
				resCh <- query.ResultOrErr{
					Err: common.NewBasicError("Error reading DB response", err)}
				return
			}
			// Check if we have a new segment.
			if segRowID != prevID {
				if curRes != nil {
					resCh <- query.ResultOrErr{Result: curRes}
				}
				curRes = &query.Result{
					LastUpdate: time.Unix(0, lastUpdated),
					Type:       segType,
				}
				var err error
				curRes.Seg, err = seg.NewSegFromRaw(common.RawBytes(rawSeg))
				if err != nil {
					resCh <- query.ResultOrErr{
						Err: common.NewBasicError("Error unmarshalling segment", err)}
					return
				}
			}
			// Append hpCfgID to result
			curRes.HpCfgIDs = append(curRes.HpCfgIDs, hpCfgID)
			prevID = segRowID
		}
		if curRes != nil {
			resCh <- query.ResultOrErr{Result: curRes}
		}
	}()
	return resCh, nil
}

func (e *executor) InsertNextQuery(ctx context.Context, src, dst addr.IA, policy pathdb.PolicyHash,
	nextQuery time.Time) (bool, error) {

	e.Lock()
	defer e.Unlock()
	if e.db == nil {
		return false, serrors.New("No database open")
	}
	if policy == nil {
		policy = pathdb.NoPolicy
	}
	// Select the data from the input only if the new NextQuery is larger than the existing
	// or if there is no existing (NextQuery.DstIsdID IS NULL)
	query := `
		INSERT OR REPLACE INTO NextQuery (SrcIsdID, SrcAsID, DstIsdID, DstAsID, Policy, NextQuery)
		SELECT data.* FROM
		(SELECT ? AS SrcIsdID, ? AS SrcAsID, ? AS DstIsdID, ? AS DstAsID, ? AS Policy, ? AS lq)
			AS data
		LEFT JOIN NextQuery USING (SrcIsdID, SrcAsID, DstIsdID, DstAsID, Policy)
		WHERE data.lq > NextQuery.NextQuery OR NextQuery.DstIsdID IS NULL;
	`
	var r sql.Result
	err := db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		r, err = tx.ExecContext(ctx, query, src.I, src.A, dst.I, dst.A, policy,
			nextQuery.UnixNano())
		return err
	})
	if err != nil {
		return false, common.NewBasicError("Failed to execute statement", err)
	}
	n, err := r.RowsAffected()
	return n > 0, err
}

func (e *executor) GetNextQuery(ctx context.Context, src, dst addr.IA,
	policy pathdb.PolicyHash) (time.Time, error) {

	e.RLock()
	defer e.RUnlock()
	if e.db == nil {
		return time.Time{}, serrors.New("No database open")
	}
	if policy == nil {
		policy = pathdb.NoPolicy
	}
	query := `
		SELECT NextQuery from NextQuery
		WHERE SrcIsdID = ? AND SrcAsID = ? AND DstIsdID = ? AND DstAsID = ? AND Policy = ?
	`
	var nanos int64
	err := e.db.QueryRowContext(ctx, query, src.I, src.A, dst.I, dst.A, policy).Scan(&nanos)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, nanos), nil
}

func (e *executor) DeleteExpiredNQ(ctx context.Context, now time.Time) (int, error) {
	return e.deleteInTx(ctx, func(tx *sql.Tx) (sql.Result, error) {
		delStmt := `DELETE FROM NextQuery WHERE NextQuery < ?`
		return tx.ExecContext(ctx, delStmt, now.UnixNano())
	})
}

func (e *executor) DeleteNQ(ctx context.Context, src, dst addr.IA,
	policy pathdb.PolicyHash) (int, error) {

	return e.deleteInTx(ctx, func(tx *sql.Tx) (sql.Result, error) {
		delStmt := `DELETE FROM NextQuery`
		var whereParts []string
		var args []interface{}
		if !src.IsZero() {
			whereParts = append(whereParts, "SrcIsdID = ? AND SrcASID = ?")
			args = append(args, src.I, src.A)
		}
		if !dst.IsZero() {
			whereParts = append(whereParts, "DstIsdID = ? AND DstASID = ?")
			args = append(args, dst.I, dst.A)
		}
		if policy != nil {
			whereParts = append(whereParts, "Policy = ?")
			args = append(args, policy)
		}
		if len(whereParts) > 0 {
			delStmt = fmt.Sprintf("%s WHERE %s", delStmt, strings.Join(whereParts, " AND "))
		}
		return tx.ExecContext(ctx, delStmt, args...)
	})
}
