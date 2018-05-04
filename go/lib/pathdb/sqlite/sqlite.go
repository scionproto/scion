// Copyright 2017 ETH Zurich
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
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb/conn"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/sqlite"
)

type segMeta struct {
	RowID       int64
	SegID       common.RawBytes
	LastUpdated time.Time
	Seg         *seg.PathSegment
}

var _ conn.Conn = (*Backend)(nil)

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

func (b *Backend) begin() error {
	if b.tx != nil {
		return common.NewBasicError("A transaction already exists", nil)
	}
	var err error
	if b.tx, err = b.db.Begin(); err != nil {
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

func (b *Backend) Insert(pseg *seg.PathSegment, segTypes []seg.Type) (int, error) {
	return b.InsertWithHPCfgIDs(pseg, segTypes, []*query.HPCfgID{&query.NullHpCfgID})
}

func (b *Backend) InsertWithHPCfgIDs(pseg *seg.PathSegment,
	segTypes []seg.Type, hpCfgIDs []*query.HPCfgID) (int, error) {
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
	meta, err := b.get(segID)
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
			if err := b.updateExisting(meta, segTypes, hpCfgIDs); err != nil {
				return 0, err
			}
			return 1, nil
		}
		return 0, nil
	}
	// Do full insert.
	if err = b.insertFull(pseg, segTypes, hpCfgIDs); err != nil {
		return 0, err
	}
	return 1, nil
}

func (b *Backend) get(segID common.RawBytes) (*segMeta, error) {
	rows, err := b.db.Query("SELECT * FROM Segments WHERE SegID=?", segID)
	if err != nil {
		return nil, common.NewBasicError("Failed to lookup segment", err)
	}
	defer rows.Close()
	for rows.Next() {
		var meta segMeta
		var lastUpdated int
		var rawSeg sql.RawBytes
		err = rows.Scan(&meta.RowID, &meta.SegID, &lastUpdated, &rawSeg)
		if err != nil {
			return nil, common.NewBasicError("Failed to extract data", err)
		}
		meta.LastUpdated = time.Unix(int64(lastUpdated), 0)
		var err error
		meta.Seg, err = seg.NewSegFromRaw(common.RawBytes(rawSeg))
		if err != nil {
			return nil, err
		}
		return &meta, nil
	}
	return nil, nil
}

func (b *Backend) updateExisting(meta *segMeta,
	segTypes []seg.Type, hpCfgIDs []*query.HPCfgID) error {
	// Create new transaction
	if err := b.begin(); err != nil {
		return err
	}
	// Update segment.
	if err := b.updateSeg(meta); err != nil {
		b.tx.Rollback()
		return err
	}
	// Check if the existing segment is registered as the given type(s).
	for _, segType := range segTypes {
		if err := b.insertType(meta.RowID, segType); err != nil {
			b.tx.Rollback()
			return err
		}
	}
	// Check if the existing segment is registered with the given hpCfgIDs.
	for _, hpCfgID := range hpCfgIDs {
		if err := b.insertHPCfgID(meta.RowID, hpCfgID); err != nil {
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

func (b *Backend) updateSeg(meta *segMeta) error {
	packedSeg, err := meta.Seg.Pack()
	if err != nil {
		return err
	}
	stmtStr := `UPDATE Segments SET LastUpdated=?, Segment=? WHERE RowID=?`
	_, err = b.tx.Exec(stmtStr, meta.LastUpdated.Unix(), packedSeg, meta.RowID)
	if err != nil {
		return common.NewBasicError("Failed to update segment", err)
	}
	return nil
}

func (b *Backend) insertType(segRowID int64, segType seg.Type) error {
	_, err := b.tx.Exec("INSERT INTO SegTypes (SegRowID, Type) VALUES (?, ?)",
		segRowID, segType)
	if err != nil {
		return common.NewBasicError("Failed to insert type", err)
	}
	return nil
}

func (b *Backend) insertHPCfgID(segRowID int64, hpCfgID *query.HPCfgID) error {
	_, err := b.tx.Exec(
		"INSERT INTO HpCfgIds (SegRowID, IsdID, AsID, CfgID) VALUES (?, ?, ?, ?)",
		segRowID, hpCfgID.IA.I, hpCfgID.IA.A, hpCfgID.ID)
	if err != nil {
		return common.NewBasicError("Failed to insert hpCfgID", err)
	}
	return nil
}

func (b *Backend) insertFull(pseg *seg.PathSegment,
	segTypes []seg.Type, hpCfgIDs []*query.HPCfgID) error {
	// Create new transaction
	if err := b.begin(); err != nil {
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
	// Insert path segment.
	inst := `INSERT INTO Segments (SegID, LastUpdated, Segment) VALUES (?, ?, ?)`
	res, err := b.tx.Exec(inst, segID, time.Now().Unix(), packedSeg)
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
	if err = b.insertInterfaces(pseg.ASEntries, segRowID); err != nil {
		b.tx.Rollback()
		return err
	}
	// Insert ISD-AS to StartsAt.
	if err = b.insertStartOrEnd(pseg.ASEntries[0], segRowID, StartsAtTable); err != nil {
		b.tx.Rollback()
		return err
	}
	// Insert ISD-AS to EndsAt.
	if err = b.insertStartOrEnd(pseg.ASEntries[pseg.MaxAEIdx()],
		segRowID, EndsAtTable); err != nil {
		b.tx.Rollback()
		return err
	}
	// Insert segType information.
	for _, segType := range segTypes {
		if err = b.insertType(segRowID, segType); err != nil {
			b.tx.Rollback()
			return err
		}
	}
	// Insert hpCfgID information.
	for _, hpCfgID := range hpCfgIDs {
		if err = b.insertHPCfgID(segRowID, hpCfgID); err != nil {
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

func (b *Backend) insertInterfaces(ases []*seg.ASEntry, segRowID int64) error {
	for _, as := range ases {
		ia := as.IA()
		stmtStr := `INSERT INTO IntfToSeg (IsdID, ASID, IntfID, SegRowID) VALUES (?, ?, ?, ?)`
		stmt, err := b.tx.Prepare(stmtStr)
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
				_, err = stmt.Exec(ia.I, ia.A, hof.ConsIngress, segRowID)
				if err != nil {
					return common.NewBasicError("Failed to insert Ingress into IntfToSeg", err)
				}
			}
			// Only insert the Egress interface for the first hop entry in an AS entry.
			if idx == 0 && hof.ConsEgress != 0 {
				_, err := stmt.Exec(ia.I, ia.A, hof.ConsEgress, segRowID)
				if err != nil {
					return common.NewBasicError("Failed to insert Egress into IntfToSeg", err)
				}
			}
		}
	}
	return nil
}

func (b *Backend) insertStartOrEnd(as *seg.ASEntry, segRowID int64,
	tableName string) error {
	ia := as.IA()
	stmtStr := fmt.Sprintf("INSERT INTO %s (IsdID, AsID, SegRowID) VALUES (?, ?, ?)", tableName)
	_, err := b.tx.Exec(stmtStr, ia.I, ia.A, segRowID)
	if err != nil {
		return common.NewBasicError(fmt.Sprintf("Failed to insert into %s", tableName), err)
	}
	return nil
}

func (b *Backend) Delete(segID common.RawBytes) (int, error) {
	b.Lock()
	defer b.Unlock()
	if b.db == nil {
		return 0, common.NewBasicError("No database open", nil)
	}
	// Create new transaction
	if err := b.begin(); err != nil {
		return 0, err
	}
	res, err := b.tx.Exec("DELETE FROM Segments WHERE SegID=?", segID)
	if err != nil {
		b.tx.Rollback()
		return 0, common.NewBasicError("Failed to delete segment", err)
	}
	// Commit transaction
	if err := b.commit(); err != nil {
		return 0, err
	}
	deleted, _ := res.RowsAffected()
	return int(deleted), nil
}

func (b *Backend) DeleteWithIntf(intf query.IntfSpec) (int, error) {
	b.Lock()
	defer b.Unlock()
	if b.db == nil {
		return 0, common.NewBasicError("No database open", nil)
	}
	// Create new transaction
	if err := b.begin(); err != nil {
		return 0, err
	}
	delStmt := `DELETE FROM Segments WHERE EXISTS (
		SELECT * FROM IntfToSeg WHERE IsdID=? AND AsID=? AND IntfID=?)`
	res, err := b.tx.Exec(delStmt, intf.IA.I, intf.IA.A, intf.IfID)
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

func (b *Backend) Get(params *query.Params) ([]*query.Result, error) {
	b.RLock()
	defer b.RUnlock()
	if b.db == nil {
		return nil, common.NewBasicError("No database open", nil)
	}
	stmt := b.buildQuery(params)
	rows, err := b.db.Query(stmt)
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
		hpCfgID := &query.HPCfgID{IA: addr.IA{}}
		err = rows.Scan(&segRowID, &rawSeg, &hpCfgID.IA.I, &hpCfgID.IA.A, &hpCfgID.ID)
		if err != nil {
			return nil, common.NewBasicError("Error reading DB response", err)
		}
		// Check if we have a new segment.
		if segRowID != prevID {
			if curRes != nil {
				res = append(res, curRes)
			}
			curRes = &query.Result{}
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

func (b *Backend) buildQuery(params *query.Params) string {
	query := []string{
		"SELECT DISTINCT s.RowID, s.Segment, h.IsdID, h.AsID, h.CfgID FROM Segments s",
		"JOIN HpCfgIds h ON h.SegRowID=s.RowID",
	}
	if params == nil {
		return strings.Join(query, "\n")
	}
	joins := []string{}
	where := []string{}
	if len(params.SegID) > 0 {
		where = append(where, fmt.Sprintf("s.SegID=x'%s'", params.SegID))
	}
	if len(params.SegTypes) > 0 {
		joins = append(joins, "JOIN SegTypes t ON t.SegRowID=s.RowID")
		subQ := []string{}
		for _, segType := range params.SegTypes {
			subQ = append(subQ, fmt.Sprintf("t.Type='%d'", segType))
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if len(params.HpCfgIDs) > 0 {
		subQ := []string{}
		for _, hpCfgID := range params.HpCfgIDs {
			subQ = append(subQ, fmt.Sprintf("(h.IsdID='%d' AND h.AsID='%d' AND h.CfgID='%d')",
				hpCfgID.IA.I, hpCfgID.IA.A, hpCfgID.ID))
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if len(params.Intfs) > 0 {
		joins = append(joins, "JOIN IntfToSeg i ON i.SegRowID=s.RowID")
		subQ := []string{}
		for _, spec := range params.Intfs {
			subQ = append(subQ, fmt.Sprintf("(i.IsdID='%d' AND i.AsID='%d' AND i.IntfID='%d')",
				spec.IA.I, spec.IA.A, spec.IfID))
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if len(params.StartsAt) > 0 {
		joins = append(joins, "JOIN StartsAt st ON st.SegRowID=s.RowID")
		subQ := []string{}
		for _, as := range params.StartsAt {
			subQ = append(subQ, fmt.Sprintf("(st.IsdID='%d' AND st.AsID='%d')", as.I, as.A))
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if len(params.EndsAt) > 0 {
		joins = append(joins, "JOIN EndsAt e ON e.SegRowID=s.RowID")
		subQ := []string{}
		for _, as := range params.EndsAt {
			subQ = append(subQ, fmt.Sprintf("(e.IsdID='%d' AND e.AsID='%d')", as.I, as.A))
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
	return strings.Join(query, "\n")
}
