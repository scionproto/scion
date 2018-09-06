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
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/sqlite"
	"github.com/scionproto/scion/go/proto"
)

type segMeta struct {
	RowID       int64
	SegID       common.RawBytes
	LastUpdated time.Time
	Seg         *seg.PathSegment
}

var _ pathdb.PathDB = (*Backend)(nil)

type Backend struct {
	sync.RWMutex
	db *sql.DB
	tx *sql.Tx
}

// New returns a new SQLite backend opening a database at the given path. If
// no database exists a new database is be created. If the schema version of the
// stored database is different from the one in schema.go, an error is returned.
func New(path string) (*Backend, error) {
	db, err := sqlite.New(path, Schema, SchemaVersion)
	if err != nil {
		return nil, err
	}
	return &Backend{
		db: db,
	}, nil
}

func (b *Backend) begin(ctx context.Context) error {
	if b.tx != nil {
		return common.NewBasicError("A transaction already exists", nil)
	}
	var err error
	if b.tx, err = b.db.BeginTx(ctx, nil); err != nil {
		return common.NewBasicError("Failed to create transaction", err)
	}
	return nil
}

func (b *Backend) commit() error {
	if b.tx == nil {
		return common.NewBasicError("No transaction to commit", nil)
	}
	if err := b.tx.Commit(); err != nil {
		b.tx = nil
		return common.NewBasicError("Failed to commit transaction", err)
	}
	b.tx = nil
	return nil
}

func (b *Backend) Insert(ctx context.Context, pseg *seg.PathSegment,
	segTypes []proto.PathSegType) (int, error) {

	return b.InsertWithHPCfgIDs(ctx, pseg, segTypes, []*query.HPCfgID{&query.NullHpCfgID})
}

func (b *Backend) InsertWithHPCfgIDs(ctx context.Context, pseg *seg.PathSegment,
	segTypes []proto.PathSegType, hpCfgIDs []*query.HPCfgID) (int, error) {
	b.Lock()
	defer b.Unlock()
	if b.db == nil {
		return 0, common.NewBasicError("No database open", nil)
	}
	// Check if we already have a path segment.
	segID, err := pseg.ID()
	if err != nil {
		return 0, err
	}
	meta, err := b.get(ctx, segID)
	if err != nil {
		return 0, err
	}
	if meta != nil {
		// Check if the new segment is more recent.
		newInfo, _ := pseg.InfoF()
		curInfo, _ := meta.Seg.InfoF()
		if newInfo.Timestamp().After(curInfo.Timestamp()) {
			// Update existing path segment.
			meta.Seg = pseg
			meta.LastUpdated = time.Now()
			if err := b.updateExisting(ctx, meta, segTypes, hpCfgIDs); err != nil {
				return 0, err
			}
			return 1, nil
		}
		return 0, nil
	}
	// Do full insert.
	if err = b.insertFull(ctx, pseg, segTypes, hpCfgIDs); err != nil {
		return 0, err
	}
	return 1, nil
}

func (b *Backend) get(ctx context.Context, segID common.RawBytes) (*segMeta, error) {
	query := "SELECT RowID, SegID, LastUpdated, Segment FROM Segments WHERE SegID=?"
	rows, err := b.db.QueryContext(ctx, query, segID)
	if err != nil {
		return nil, common.NewBasicError("Failed to lookup segment", err)
	}
	defer rows.Close()
	for rows.Next() {
		var meta segMeta
		var lastUpdated int64
		var rawSeg sql.RawBytes
		err = rows.Scan(&meta.RowID, &meta.SegID, &lastUpdated, &rawSeg)
		if err != nil {
			return nil, common.NewBasicError("Failed to extract data", err)
		}
		meta.LastUpdated = time.Unix(lastUpdated, 0)
		var err error
		meta.Seg, err = seg.NewSegFromRaw(common.RawBytes(rawSeg))
		if err != nil {
			return nil, err
		}
		return &meta, nil
	}
	return nil, nil
}

func (b *Backend) updateExisting(ctx context.Context, meta *segMeta,
	segTypes []proto.PathSegType, hpCfgIDs []*query.HPCfgID) error {

	// Create new transaction
	if err := b.begin(ctx); err != nil {
		return err
	}
	// Update segment.
	if err := b.updateSeg(ctx, meta); err != nil {
		b.tx.Rollback()
		return err
	}
	// Check if the existing segment is registered as the given type(s).
	for _, segType := range segTypes {
		if err := b.insertType(ctx, meta.RowID, segType); err != nil {
			b.tx.Rollback()
			return err
		}
	}
	// Check if the existing segment is registered with the given hpCfgIDs.
	for _, hpCfgID := range hpCfgIDs {
		if err := b.insertHPCfgID(ctx, meta.RowID, hpCfgID); err != nil {
			b.tx.Rollback()
			return err
		}
	}
	// Commit transaction
	if err := b.commit(); err != nil {
		return err
	}
	return nil
}

func (b *Backend) updateSeg(ctx context.Context, meta *segMeta) error {
	packedSeg, err := meta.Seg.Pack()
	if err != nil {
		return err
	}
	exp := meta.Seg.MaxExpiry().Unix()
	stmtStr := `UPDATE Segments SET LastUpdated=?, Segment=?, Expiry=? WHERE RowID=?`
	_, err = b.tx.ExecContext(ctx, stmtStr, meta.LastUpdated.Unix(), packedSeg, exp, meta.RowID)
	if err != nil {
		return common.NewBasicError("Failed to update segment", err)
	}
	return nil
}

func (b *Backend) insertType(ctx context.Context, segRowID int64,
	segType proto.PathSegType) error {

	_, err := b.tx.ExecContext(ctx, "INSERT INTO SegTypes (SegRowID, Type) VALUES (?, ?)",
		segRowID, segType)
	if err != nil {
		return common.NewBasicError("Failed to insert type", err)
	}
	return nil
}

func (b *Backend) insertHPCfgID(ctx context.Context, segRowID int64,
	hpCfgID *query.HPCfgID) error {

	_, err := b.tx.ExecContext(ctx,
		"INSERT INTO HpCfgIds (SegRowID, IsdID, AsID, CfgID) VALUES (?, ?, ?, ?)",
		segRowID, hpCfgID.IA.I, hpCfgID.IA.A, hpCfgID.ID)
	if err != nil {
		return common.NewBasicError("Failed to insert hpCfgID", err)
	}
	return nil
}

func (b *Backend) insertFull(ctx context.Context, pseg *seg.PathSegment,
	segTypes []proto.PathSegType, hpCfgIDs []*query.HPCfgID) error {

	// Create new transaction
	if err := b.begin(ctx); err != nil {
		return err
	}
	segID, err := pseg.ID()
	if err != nil {
		return err
	}
	packedSeg, err := pseg.Pack()
	if err != nil {
		return err
	}
	exp := pseg.MaxExpiry().Unix()
	// Insert path segment.
	inst := `INSERT INTO Segments (SegID, LastUpdated, Segment, Expiry) VALUES (?, ?, ?, ?)`
	res, err := b.tx.ExecContext(ctx, inst, segID, time.Now().Unix(), packedSeg, exp)
	if err != nil {
		b.tx.Rollback()
		return common.NewBasicError("Failed to insert path segment", err)
	}
	segRowID, err := res.LastInsertId()
	if err != nil {
		b.tx.Rollback()
		return common.NewBasicError("Failed to retrieve segRowID of inserted segment", err)
	}
	// Insert all interfaces.
	if err = b.insertInterfaces(ctx, pseg.ASEntries, segRowID); err != nil {
		b.tx.Rollback()
		return err
	}
	// Insert ISD-AS to StartsAt.
	if err = b.insertStartOrEnd(ctx, pseg.ASEntries[0], segRowID, StartsAtTable); err != nil {
		b.tx.Rollback()
		return err
	}
	// Insert ISD-AS to EndsAt.
	if err = b.insertStartOrEnd(ctx, pseg.ASEntries[pseg.MaxAEIdx()],
		segRowID, EndsAtTable); err != nil {
		b.tx.Rollback()
		return err
	}
	// Insert segType information.
	for _, segType := range segTypes {
		if err = b.insertType(ctx, segRowID, segType); err != nil {
			b.tx.Rollback()
			return err
		}
	}
	// Insert hpCfgID information.
	for _, hpCfgID := range hpCfgIDs {
		if err = b.insertHPCfgID(ctx, segRowID, hpCfgID); err != nil {
			b.tx.Rollback()
			return err
		}
	}
	// Commit transaction
	if err = b.commit(); err != nil {
		return err
	}
	return nil
}

func (b *Backend) insertInterfaces(ctx context.Context,
	ases []*seg.ASEntry, segRowID int64) error {

	for _, as := range ases {
		ia := as.IA()
		stmtStr := `INSERT INTO IntfToSeg (IsdID, ASID, IntfID, SegRowID) VALUES (?, ?, ?, ?)`
		stmt, err := b.tx.PrepareContext(ctx, stmtStr)
		if err != nil {
			return common.NewBasicError("Failed to prepare insert into IntfToSeg", err)
		}
		defer stmt.Close()
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

func (b *Backend) insertStartOrEnd(ctx context.Context, as *seg.ASEntry,
	segRowID int64, tableName string) error {

	ia := as.IA()
	stmtStr := fmt.Sprintf("INSERT INTO %s (IsdID, AsID, SegRowID) VALUES (?, ?, ?)", tableName)
	_, err := b.tx.ExecContext(ctx, stmtStr, ia.I, ia.A, segRowID)
	if err != nil {
		return common.NewBasicError(fmt.Sprintf("Failed to insert into %s", tableName), err)
	}
	return nil
}

func (b *Backend) Delete(ctx context.Context, segID common.RawBytes) (int, error) {
	return b.deleteInTrx(ctx, func() (sql.Result, error) {
		return b.tx.ExecContext(ctx, "DELETE FROM Segments WHERE SegID=?", segID)
	})
}

func (b *Backend) DeleteWithIntf(ctx context.Context, intf query.IntfSpec) (int, error) {
	return b.deleteInTrx(ctx, func() (sql.Result, error) {
		delStmt := `DELETE FROM Segments WHERE EXISTS (
			SELECT * FROM IntfToSeg WHERE IsdID=? AND AsID=? AND IntfID=?)`
		return b.tx.ExecContext(ctx, delStmt, intf.IA.I, intf.IA.A, intf.IfID)
	})
}

func (b *Backend) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	return b.deleteInTrx(ctx, func() (sql.Result, error) {
		delStmt := `DELETE FROM Segments WHERE Expiry < ?`
		return b.tx.ExecContext(ctx, delStmt, now.Unix())
	})
}

func (b *Backend) deleteInTrx(ctx context.Context, delete func() (sql.Result, error)) (int, error) {
	b.Lock()
	defer b.Unlock()
	if b.db == nil {
		return 0, common.NewBasicError("No database open", nil)
	}
	// Create new transaction
	if err := b.begin(ctx); err != nil {
		return 0, err
	}
	res, err := delete()
	if err != nil {
		b.tx.Rollback()
		return 0, common.NewBasicError("Failed to delete segments", err)
	}
	// Commit transaction
	if err := b.commit(); err != nil {
		return 0, err
	}
	deleted, _ := res.RowsAffected()
	return int(deleted), nil
}

func (b *Backend) Get(ctx context.Context, params *query.Params) ([]*query.Result, error) {
	b.RLock()
	defer b.RUnlock()
	if b.db == nil {
		return nil, common.NewBasicError("No database open", nil)
	}
	stmt, args := b.buildQuery(params)
	rows, err := b.db.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, common.NewBasicError("Error looking up path segment", err, "q", stmt)
	}
	defer rows.Close()
	res := []*query.Result{}
	prevID := -1
	var curRes *query.Result
	for rows.Next() {
		var segRowID int
		var rawSeg sql.RawBytes
		var lastUpdated int64
		hpCfgID := &query.HPCfgID{IA: addr.IA{}}
		err = rows.Scan(&segRowID, &rawSeg, &lastUpdated, &hpCfgID.IA.I, &hpCfgID.IA.A, &hpCfgID.ID)
		if err != nil {
			return nil, common.NewBasicError("Error reading DB response", err)
		}
		// Check if we have a new segment.
		if segRowID != prevID {
			if curRes != nil {
				res = append(res, curRes)
			}
			curRes = &query.Result{
				LastUpdate: time.Unix(lastUpdated, 0),
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

func (b *Backend) buildQuery(params *query.Params) (string, []interface{}) {
	var args []interface{}
	query := []string{
		"SELECT DISTINCT s.RowID, s.Segment, s.LastUpdated," +
			" h.IsdID, h.AsID, h.CfgID FROM Segments s",
		"JOIN HpCfgIds h ON h.SegRowID=s.RowID",
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
		joins = append(joins, "JOIN SegTypes t ON t.SegRowID=s.RowID")
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
		joins = append(joins, "JOIN StartsAt st ON st.SegRowID=s.RowID")
		subQ := []string{}
		for _, as := range params.StartsAt {
			if as.A == 0 {
				subQ = append(subQ, "(st.IsdID=?)")
				args = append(args, as.I)
			} else {
				subQ = append(subQ, "(st.IsdID=? AND st.AsID=?)")
				args = append(args, as.I, as.A)
			}
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if len(params.EndsAt) > 0 {
		joins = append(joins, "JOIN EndsAt e ON e.SegRowID=s.RowID")
		subQ := []string{}
		for _, as := range params.EndsAt {
			if as.A == 0 {
				subQ = append(subQ, "(e.IsdID=?)")
				args = append(args, as.I)
			} else {
				subQ = append(subQ, "(e.IsdID=? AND e.AsID=?)")
				args = append(args, as.I, as.A)
			}
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if params.MinLastUpdate != nil {
		where = append(where, "(s.LastUpdated>?)")
		args = append(args, params.MinLastUpdate.Unix())
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
