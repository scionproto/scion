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

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/pathdb/query"
	"github.com/scionproto/scion/private/storage/db"
	"github.com/scionproto/scion/private/storage/path"
	"github.com/scionproto/scion/private/storage/utils"
)

type segMeta struct {
	RowID       int64
	SegID       []byte
	FullID      []byte
	LastUpdated time.Time
	Seg         *seg.PathSegment
}

var noInsertion = pathdb.InsertStats{}

var _ pathdb.DB = (*Backend)(nil)

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
		return nil, serrors.Wrap("Failed to create transaction", err)
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
	// XXX(shitz): The way the SQL queries are built requires each path segment to be registered
	// with a 0 hidden path group id.
	return e.InsertWithHPGroupIDs(ctx, segMeta, []uint64{0})
}

func (e *executor) InsertWithHPGroupIDs(ctx context.Context, segMeta *seg.Meta,
	hpGroupIDs []uint64) (pathdb.InsertStats, error) {

	e.Lock()
	defer e.Unlock()
	if e.db == nil {
		return noInsertion, serrors.New("No database open")
	}
	var stats pathdb.InsertStats
	err := db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		stats, err = insert(ctx, tx, segMeta, hpGroupIDs)
		return err
	})
	return stats, err
}

func insert(ctx context.Context, tx *sql.Tx, segMeta *seg.Meta,
	hpGroupIDs []uint64) (pathdb.InsertStats, error) {

	pseg := segMeta.Segment
	segID := pseg.ID()
	newFullID := pseg.FullID()
	meta, err := get(ctx, tx, segID)
	if err != nil {
		return pathdb.InsertStats{}, err
	}
	// Do full insert.
	if meta == nil {
		err := insertFull(ctx, tx, segMeta.Segment, []seg.Type{segMeta.Type}, hpGroupIDs)
		if err != nil {
			return pathdb.InsertStats{}, err
		}
		return pathdb.InsertStats{Inserted: 1}, nil
	}
	newLastHopVersion, err := utils.ExtractLastHopVersion(pseg)
	if err != nil {
		return pathdb.InsertStats{}, err
	}
	oldLastHopVersion, err := utils.ExtractLastHopVersion(meta.Seg)
	if err != nil {
		return pathdb.InsertStats{}, err
	}
	// If the segment is older than the one already present in the pathDB
	if newLastHopVersion <= oldLastHopVersion {
		return pathdb.InsertStats{}, nil
	}
	// Update the existing segment
	meta.Seg = pseg
	meta.LastUpdated = time.Now()
	err = updateExisting(ctx, tx, meta, []seg.Type{segMeta.Type}, newFullID, hpGroupIDs)
	if err != nil {
		return pathdb.InsertStats{}, err
	}
	return pathdb.InsertStats{Updated: 1}, nil
}

func get(ctx context.Context, tx *sql.Tx, segID []byte) (*segMeta, error) {
	query := "SELECT RowID, SegID, FullID, LastUpdated, Segment FROM Segments WHERE SegID=?"
	var meta segMeta
	var lastUpdated int64
	var rawSeg []byte
	err := tx.QueryRowContext(ctx, query, segID).Scan(
		&meta.RowID, &meta.SegID, &meta.FullID, &lastUpdated, &rawSeg)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, serrors.Wrap("Failed to lookup segment", err)
	}
	meta.LastUpdated = time.Unix(0, lastUpdated)
	meta.Seg, err = pathdb.UnpackSegment(rawSeg)
	if err != nil {
		return nil, err
	}
	return &meta, nil
}

func updateExisting(ctx context.Context, tx *sql.Tx, meta *segMeta,
	types []seg.Type, newFullID []byte, hpGroupIDs []uint64) error {

	// Update segment.
	if err := updateSeg(ctx, tx, meta); err != nil {
		return err
	}
	// Make sure the existing segment is registered as the given type.
	for _, t := range types {
		if err := insertType(ctx, tx, meta.RowID, t); err != nil {
			return err
		}
	}
	// Check if the existing segment is registered with the given hpGroupIDs.
	for _, hpGroupID := range hpGroupIDs {
		if err := insertHPGroupID(ctx, tx, meta.RowID, hpGroupID); err != nil {
			return err
		}
	}
	// Update the IntfToSeg table
	if !bytes.Equal(newFullID, meta.FullID) {
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
}

func updateSeg(ctx context.Context, tx *sql.Tx, meta *segMeta) error {
	packedSeg, err := pathdb.PackSegment(meta.Seg)
	if err != nil {
		return err
	}
	exp := meta.Seg.MaxExpiry().Unix()
	fullID := meta.Seg.FullID()
	stmtStr := `UPDATE Segments SET FullID=?, LastUpdated=?, InfoTs=?, Segment=?, MaxExpiry=?
				WHERE RowID=?`
	_, err = tx.ExecContext(ctx, stmtStr,
		fullID, meta.LastUpdated.UnixNano(), meta.Seg.Info.Timestamp, packedSeg, exp, meta.RowID)
	if err != nil {
		return serrors.Wrap("Failed to update segment", err)
	}
	return nil
}

func insertType(ctx context.Context, tx *sql.Tx, segRowID int64,
	segType seg.Type) error {

	_, err := tx.ExecContext(ctx, "INSERT INTO SegTypes (SegRowID, Type) VALUES (?, ?)",
		segRowID, segType)
	if err != nil {
		return serrors.Wrap("Failed to insert type", err)
	}
	return nil
}

func insertHPGroupID(ctx context.Context, tx *sql.Tx, segRowID int64,
	hpGroupID uint64) error {

	// Need to cast the hpGroupID to int64 due to
	// https://github.com/golang/go/blob/912f0750472dd4f674b69ca1616bfaf377af1805/src/database/sql/driver/types.go#L266-L275
	_, err := tx.ExecContext(ctx,
		"INSERT INTO HPGroupIDs (SegRowID, GroupID) VALUES (?, ?)",
		segRowID, int64(hpGroupID))
	if err != nil {
		return serrors.Wrap("Failed to insert hpGroupID", err)
	}
	return nil
}

func insertFull(ctx context.Context, tx *sql.Tx, pseg *seg.PathSegment, types []seg.Type,
	hpGroupIDs []uint64) error {

	segID := pseg.ID()
	fullID := pseg.FullID()
	packedSeg, err := pathdb.PackSegment(pseg)
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
		pseg.Info.Timestamp.UnixNano(), packedSeg, exp, st.ISD(), st.AS(), end.ISD(), end.AS())
	if err != nil {
		return serrors.Wrap("Failed to insert path segment", err)
	}
	segRowID, err := res.LastInsertId()
	if err != nil {
		return serrors.Wrap("Failed to retrieve segRowID of inserted segment", err)
	}
	// Insert all interfaces.
	if err = insertInterfaces(ctx, tx, pseg.ASEntries, segRowID); err != nil {
		return err
	}
	// Insert segType information.
	for _, t := range types {
		if err = insertType(ctx, tx, segRowID, t); err != nil {
			return err
		}
	}
	// Insert hpGroupID information.
	// XXX(shitz): The way the SQL queries are built requires each path segment to be registered
	// with a 0 hidden path group id (if there is not a different one set).
	if len(hpGroupIDs) == 0 {
		hpGroupIDs = append(hpGroupIDs, 0)
	}
	for _, hpGroupID := range hpGroupIDs {
		if err = insertHPGroupID(ctx, tx, segRowID, hpGroupID); err != nil {
			return err
		}
	}
	return nil
}

func insertInterfaces(ctx context.Context, tx *sql.Tx, ases []seg.ASEntry, segRowID int64) error {
	stmtStr := `INSERT INTO IntfToSeg (IsdID, AsID, IntfID, SegRowID) VALUES (?, ?, ?, ?)`
	stmt, err := tx.PrepareContext(ctx, stmtStr)
	if err != nil {
		return serrors.Wrap("Failed to prepare insert into IntfToSeg", err)
	}
	defer stmt.Close()
	for _, as := range ases {
		ia := as.Local

		hof := as.HopEntry.HopField
		if hof.ConsIngress != 0 {
			_, err = stmt.ExecContext(ctx, ia.ISD(), ia.AS(), hof.ConsIngress, segRowID)
			if err != nil {
				return serrors.Wrap("inserting Ingress into IntfToSeg", err)
			}
		}
		if hof.ConsEgress != 0 {
			_, err := stmt.ExecContext(ctx, ia.ISD(), ia.AS(), hof.ConsEgress, segRowID)
			if err != nil {
				return serrors.Wrap("inserting Egress into IntfToSeg", err)
			}
		}
		// Only insert the Egress interface for the regular hop entry in an AS entry.

		for i, peer := range as.PeerEntries {
			hof := peer.HopField
			if hof.ConsIngress != 0 {
				_, err = stmt.ExecContext(ctx, ia.ISD(), ia.AS(), hof.ConsIngress, segRowID)
				if err != nil {
					return serrors.Wrap("insert peering Ingress into IntfToSeg", err, "index", i)
				}
			}
		}
	}
	return nil
}

func (e *executor) DeleteSegment(ctx context.Context, partialID string) error {
	_, err := e.deleteInTx(ctx, func(tx *sql.Tx) (sql.Result, error) {
		delStmt := `DELETE FROM Segments WHERE hex(SegID) LIKE ?`
		return tx.ExecContext(ctx, delStmt, partialID+"%")
	})
	return err
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
		return nil, serrors.Wrap("Error looking up path segment", err, "q", stmt)
	}
	defer rows.Close()
	var res []*query.Result
	for rows.Next() {
		var segRowID int
		var rawSeg sql.RawBytes
		var lastUpdated int64
		var segTypes path.SegTypes
		var hpGroupIDs path.GroupIDs
		if err = rows.Scan(
			&segRowID, &rawSeg, &lastUpdated, &segTypes, &hpGroupIDs); err != nil {

			return nil, serrors.Wrap("Error reading DB response", err)
		}
		parsed, err := pathdb.UnpackSegment(rawSeg)
		if err != nil {
			return nil, serrors.Wrap("unmarshalling segment", err)
		}
		for _, t := range segTypes {
			res = append(res, &query.Result{
				LastUpdate: time.Unix(0, lastUpdated),
				Type:       t,
				Seg:        parsed,
				HPGroupIDs: []uint64(hpGroupIDs),
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

func (e *executor) buildQuery(params *query.Params) (string, []any) {
	var args []any
	query := []string{
		"SELECT DISTINCT s.RowID, s.Segment, s.LastUpdated, group_concat(DISTINCT t.Type), " +
			"group_concat(DISTINCT h.GroupID) FROM Segments s",
		"JOIN SegTypes t ON t.SegRowID=s.RowID",
		"JOIN HPGroupIDs h ON h.SegRowID=s.RowID",
	}
	if params == nil {
		query = append(query, "GROUP BY s.RowID")
		query = append(query, "ORDER BY s.RowID ASC")
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
	if len(params.HPGroupIDs) > 0 {
		subQ := []string{}
		for _, hpGroupID := range params.HPGroupIDs {
			subQ = append(subQ, "(h.GroupID=?)")
			args = append(args, int64(hpGroupID))
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if len(params.Intfs) > 0 {
		joins = append(joins, "JOIN IntfToSeg i ON i.SegRowID=s.RowID")
		subQ := []string{}
		for _, spec := range params.Intfs {
			subQ = append(subQ, "(i.IsdID=? AND i.AsID=? AND i.IntfID=?)")
			args = append(args, spec.IA.ISD(), spec.IA.AS(), spec.IfID)
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if len(params.StartsAt) > 0 {
		subQ := []string{}
		for _, as := range params.StartsAt {
			if as.AS() == 0 {
				subQ = append(subQ, "(s.StartIsdID=?)")
				args = append(args, as.ISD())
			} else {
				subQ = append(subQ, "(s.StartIsdID=? AND s.StartAsID=?)")
				args = append(args, as.ISD(), as.AS())
			}
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if len(params.EndsAt) > 0 {
		subQ := []string{}
		for _, as := range params.EndsAt {
			if as.AS() == 0 {
				subQ = append(subQ, "(s.EndIsdID=?)")
				args = append(args, as.ISD())
			} else {
				subQ = append(subQ, "(s.EndIsdID=? AND s.EndAsID=?)")
				args = append(args, as.ISD(), as.AS())
			}
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	// Assemble the query.
	if len(joins) > 0 {
		query = append(query, strings.Join(joins, "\n"))
	}
	if len(where) > 0 {
		query = append(query, fmt.Sprintf("WHERE %s", strings.Join(where, " AND\n")))
	}
	query = append(query, "GROUP BY s.RowID")
	query = append(query, "ORDER BY s.RowID ASC")
	return strings.Join(query, "\n"), args
}

func (e *executor) GetAll(ctx context.Context) (query.Results, error) {
	return e.Get(ctx, nil)
}

func (e *executor) InsertNextQuery(ctx context.Context, src, dst addr.IA,
	nextQuery time.Time) (bool, error) {

	e.Lock()
	defer e.Unlock()
	if e.db == nil {
		return false, serrors.New("No database open")
	}
	// Select the data from the input only if the new NextQuery is larger than the existing
	// or if there is no existing (NextQuery.DstIsdID IS NULL)
	query := `
		INSERT OR REPLACE INTO NextQuery (SrcIsdID, SrcAsID, DstIsdID, DstAsID, NextQuery)
		SELECT data.* FROM
		(SELECT ? AS SrcIsdID, ? AS SrcAsID, ? AS DstIsdID, ? AS DstAsID, ? AS lq)
			AS data
		LEFT JOIN NextQuery USING (SrcIsdID, SrcAsID, DstIsdID, DstAsID)
		WHERE data.lq > NextQuery.NextQuery OR NextQuery.DstIsdID IS NULL;
	`
	var r sql.Result
	err := db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		r, err = tx.ExecContext(
			ctx,
			query,
			src.ISD(),
			src.AS(),
			dst.ISD(),
			dst.AS(),
			nextQuery.UnixNano(),
		)
		return err
	})
	if err != nil {
		return false, serrors.Wrap("Failed to execute statement", err)
	}
	n, err := r.RowsAffected()
	return n > 0, err
}

func (e *executor) GetNextQuery(ctx context.Context, src, dst addr.IA) (time.Time, error) {
	e.RLock()
	defer e.RUnlock()
	if e.db == nil {
		return time.Time{}, serrors.New("No database open")
	}
	query := `
		SELECT NextQuery from NextQuery
		WHERE SrcIsdID = ? AND SrcAsID = ? AND DstIsdID = ? AND DstAsID = ?
	`
	var nanos int64
	err := e.db.QueryRowContext(ctx, query, src.ISD(), src.AS(), dst.ISD(), dst.AS()).Scan(&nanos)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, nanos), nil
}
