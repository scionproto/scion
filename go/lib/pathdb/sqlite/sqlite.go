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

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl/seg"
	"github.com/netsec-ethz/scion/go/lib/pathdb/conn"
	"github.com/netsec-ethz/scion/go/lib/pathdb/query"
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
}

// New returns a new SQLite backend opening a database at the given path. If
// no database exists a new database is be created. If the schema version of the
// stored database is different from the one in schema.go, an error is returned.
func New(path string) (*Backend, *common.Error) {
	b := &Backend{}
	if cerr := b.open(path); cerr != nil {
		return nil, cerr
	}
	// Check the schema version and set up new DB if necessary.
	var version int
	err := b.db.QueryRow("PRAGMA user_version;").Scan(&version)
	if err != nil {
		return nil, common.NewError("Failed to check schema version", "err", err)
	}
	if version == 0 {
		if cerr := b.setup(); cerr != nil {
			return nil, cerr
		}
	} else if version != SchemaVersion {
		return nil, common.NewError("Database schema version mismatch",
			"expected", SchemaVersion, "have", version)
	}
	return b, nil
}

func (b *Backend) open(path string) *common.Error {
	b.Lock()
	defer b.Unlock()
	// Add foreign_key parameter to path to enable foreign key support.
	uri := fmt.Sprintf("%s?_foreign_keys=1", path)
	var err error
	if b.db, err = sql.Open("sqlite3", uri); err != nil {
		return common.NewError("Couldn't open SQLite database", "err", err)
	}
	// Ensure foreign keys are supported and enabled.
	var enabled bool
	err = b.db.QueryRow("PRAGMA foreign_keys;").Scan(&enabled)
	if err == sql.ErrNoRows {
		return common.NewError("Foreign keys not supported", "err", err)
	}
	if err != nil {
		return common.NewError("Failed to check for foreign key support", "err", err)
	}
	if !enabled {
		return common.NewError("Failed to enable foreign key support")
	}
	return nil
}

func (b *Backend) setup() *common.Error {
	b.Lock()
	defer b.Unlock()
	if b.db == nil {
		return common.NewError("No database open")
	}
	_, err := b.db.Exec(Schema)
	if err != nil {
		return common.NewError("Failed to set up SQLite database", "err", err)
	}
	// Write schema version to database.
	_, err = b.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion))
	if err != nil {
		return common.NewError("Failed to write schema version", "err", err)
	}
	return nil
}

func (b *Backend) close() *common.Error {
	b.Lock()
	defer b.Unlock()
	if b.db == nil {
		return common.NewError("No database open")
	}
	if err := b.db.Close(); err != nil {
		return common.NewError("Failed to close SQLite database", "err", err)
	}
	return nil
}

func (b *Backend) Insert(pseg *seg.PathSegment, segTypes []seg.Type) (int, *common.Error) {
	return b.InsertWithHPCfgIDs(pseg, segTypes, []*query.HPCfgID{&query.NullCfgID})
}

func (b *Backend) InsertWithHPCfgIDs(pseg *seg.PathSegment,
	segTypes []seg.Type, cfgIDs []*query.HPCfgID) (int, *common.Error) {
	b.Lock()
	defer b.Unlock()
	if b.db == nil {
		return 0, common.NewError("No database open")
	}
	// Check if we already have a path segment.
	segID := pseg.ID()
	meta, err := b.get(segID)
	if err != nil {
		return 0, err
	}
	if meta != nil {
		// Check if the new segment is more recent.
		newInfo, _ := pseg.Info()
		curInfo, _ := meta.Seg.Info()
		if newInfo.Timestamp().After(curInfo.Timestamp()) {
			// Update existing path segment.
			meta.Seg = pseg
			meta.LastUpdated = time.Now()
			if err := b.updateExisting(meta, segTypes, cfgIDs); err != nil {
				return 0, err
			}
			return 1, nil
		}
		return 0, nil
	}
	// Do full insert.
	err = b.insertFull(pseg, segTypes, cfgIDs)
	if err != nil {
		return 0, err
	}
	return 1, nil
}

func (b *Backend) get(segID common.RawBytes) (*segMeta, *common.Error) {
	rows, err := b.db.Query("SELECT * FROM Segments WHERE SegID=?", segID)
	if err != nil {
		return nil, common.NewError("Failed to lookup segment", "err", err)
	}
	defer rows.Close()
	for rows.Next() {
		var meta segMeta
		var lastUpdated int
		var rawSeg sql.RawBytes
		err = rows.Scan(&meta.RowID, &meta.SegID, &lastUpdated, &rawSeg)
		if err != nil {
			return nil, common.NewError("Failed to extract data", "err", err)
		}
		meta.LastUpdated = time.Unix(int64(lastUpdated), 0)
		var cerr *common.Error
		meta.Seg, cerr = seg.NewFromRaw(common.RawBytes(rawSeg))
		if cerr != nil {
			return nil, cerr
		}
		return &meta, nil
	}
	return nil, nil
}

func (b *Backend) updateExisting(meta *segMeta,
	segTypes []seg.Type, cfgIDs []*query.HPCfgID) *common.Error {
	tx, err := b.db.Begin()
	if err != nil {
		return common.NewError("Failed to create transaction", "err", err)
	}
	// Update segment.
	if cerr := updateSeg(tx, meta); cerr != nil {
		tx.Rollback()
		return cerr
	}
	// Check if the existing segment is registered as the given type(s).
	for _, segType := range segTypes {
		if cerr := insertType(tx, meta.RowID, segType); cerr != nil {
			tx.Rollback()
			return cerr
		}
	}
	// Check if the existing segment is registered with the given cfgIDs.
	for _, cfgID := range cfgIDs {
		if cerr := insertHPCfgID(tx, meta.RowID, cfgID); cerr != nil {
			tx.Rollback()
			return cerr
		}
	}
	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return common.NewError("Failed to commit transaction", "err", err)
	}
	return nil
}

func updateSeg(tx *sql.Tx, meta *segMeta) *common.Error {
	packedSeg, cerr := meta.Seg.Pack()
	if cerr != nil {
		return cerr
	}
	stmtStr := `UPDATE Segments SET LastUpdated=?, Segment=? WHERE RowID=?`
	_, err := prepareAndExec(tx, stmtStr, meta.LastUpdated.Unix(), packedSeg, meta.RowID)
	if err != nil {
		return common.NewError("Failed to update segment", "err", err)
	}
	return nil
}

func prepareAndExec(tx *sql.Tx, inst string, args ...interface{}) (sql.Result, *common.Error) {
	stmt, err := tx.Prepare(inst)
	if err != nil {
		return nil, common.NewError("Failed to prepare statement", "stmt", inst, "err", err)
	}
	res, err := stmt.Exec(args...)
	if err != nil {
		return nil, common.NewError("Failed to execute statement", "stmt", inst, "err", err)
	}
	return res, nil
}

func insertType(tx *sql.Tx, segRowID int64, segType seg.Type) *common.Error {
	_, err := prepareAndExec(tx, "INSERT INTO SegTypes (SegRowID, Type) VALUES (?, ?)",
		segRowID, segType)
	if err != nil {
		return common.NewError("Faild to insert type", "err", err)
	}
	return nil
}

func insertHPCfgID(tx *sql.Tx, segRowID int64, cfgID *query.HPCfgID) *common.Error {
	_, err := prepareAndExec(
		tx, "INSERT INTO HPCfgIds (SegRowID, IsdID, AsID, CfgID) VALUES (?, ?, ?, ?)",
		segRowID, cfgID.IA.I, cfgID.IA.A, cfgID.ID)
	if err != nil {
		return common.NewError("Faild to insert cfgID", "err", err)
	}
	return nil
}

func (b *Backend) insertFull(pseg *seg.PathSegment,
	segTypes []seg.Type, cfgIDs []*query.HPCfgID) *common.Error {
	tx, err := b.db.Begin()
	if err != nil {
		return common.NewError("Failed to create transaction", "err", err)
	}
	segID := pseg.ID()
	packedSeg, cerr := pseg.Pack()
	if cerr != nil {
		return cerr
	}
	// Insert path segment.
	inst := `INSERT INTO Segments (SegID, LastUpdated, Segment) VALUES (?, ?, ?)`
	res, cerr := prepareAndExec(tx, inst, segID, time.Now().Unix(), packedSeg)
	if cerr != nil {
		tx.Rollback()
		return common.NewError("Failed to insert path segment", "err", cerr)
	}
	segRowID, err := res.LastInsertId()
	if err != nil {
		tx.Rollback()
		return common.NewError("Failed to retrieve segRowID of inserted segment", "err", err)
	}
	// Insert all interfaces.
	cerr = insertInterfaces(tx, pseg.ASEntries, segRowID)
	if cerr != nil {
		tx.Rollback()
		return cerr
	}
	// Insert ISD-AS to StartsAt.
	cerr = insertStartOrEnd(tx, pseg.ASEntries[0], segRowID, "StartsAt")
	if cerr != nil {
		tx.Rollback()
		return cerr
	}
	// Insert ISD-AS to EndsAt.
	cerr = insertStartOrEnd(tx, pseg.ASEntries[len(pseg.ASEntries)-1], segRowID, "EndsAt")
	if cerr != nil {
		tx.Rollback()
		return cerr
	}
	// Insert segType information.
	for _, segType := range segTypes {
		cerr = insertType(tx, segRowID, segType)
		if cerr != nil {
			tx.Rollback()
			return cerr
		}
	}
	// Insert cfgID information.
	for _, cfgID := range cfgIDs {
		cerr = insertHPCfgID(tx, segRowID, cfgID)
		if cerr != nil {
			tx.Rollback()
			return cerr
		}
	}
	// Commit transaction
	err = tx.Commit()
	if cerr != nil {
		return common.NewError("Failed to commit transaction", "err", err)
	}
	return nil
}

func insertInterfaces(tx *sql.Tx, ases []*seg.ASEntry, segRowID int64) *common.Error {
	for _, as := range ases {
		ia := as.IA()
		stmtStr := `INSERT INTO IntfToSeg (IsdID, ASID, IntfID, SegRowID) VALUES (?, ?, ?, ?)`
		stmt, err := tx.Prepare(stmtStr)
		if err != nil {
			return common.NewError("Failed to prepare insert into IntfToSeg", "err", err)
		}
		defer stmt.Close()
		for idx, hop := range as.HopEntries {
			hof, cerr := hop.HopField()
			if cerr != nil {
				return common.NewError("Failed to extract hop field", "err", cerr)
			}
			if hof.Egress != 0 {
				_, err := stmt.Exec(ia.I, ia.A, hof.Egress, segRowID)
				if err != nil {
					return common.NewError("Failed to insert Egress into IntfToSeg", "err", err)
				}
			}
			// Only insert the Ingress interface for the first hop entry in an AS entry.
			if idx == 0 && hof.Ingress != 0 {
				_, err = stmt.Exec(ia.I, ia.A, hof.Ingress, segRowID)
				if err != nil {
					return common.NewError("Failed to insert Ingress into IntfToSeg", "err", err)
				}
			}
		}
	}
	return nil
}

func insertStartOrEnd(tx *sql.Tx, as *seg.ASEntry,
	segRowID int64, tableName string) *common.Error {
	ia := as.IA()
	stmtStr := fmt.Sprintf("INSERT INTO %s (IsdID, AsID, SegRowID) VALUES (?, ?, ?)", tableName)
	_, err := prepareAndExec(tx, stmtStr, ia.I, ia.A, segRowID)
	if err != nil {
		return common.NewError(fmt.Sprintf("Failed to insert into %s", tableName), "err", err)
	}
	return nil
}

func (b *Backend) Delete(segID common.RawBytes) (int, *common.Error) {
	b.Lock()
	defer b.Unlock()
	if b.db == nil {
		return 0, common.NewError("No database open")
	}
	tx, err := b.db.Begin()
	if err != nil {
		return 0, common.NewError("Failed to create transaction", "err", err)
	}
	res, cerr := prepareAndExec(tx, "DELETE FROM Segments WHERE SegID=?", segID)
	if cerr != nil {
		tx.Rollback()
		return 0, common.NewError("Failed to delete segment", "err", cerr)
	}
	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return 0, common.NewError("Failed to commit transaction", "err", err)
	}
	deleted, _ := res.RowsAffected()
	return int(deleted), nil
}

func (b *Backend) DeleteWithIntf(intf query.IntfSpec) (int, *common.Error) {
	b.Lock()
	defer b.Unlock()
	if b.db == nil {
		return 0, common.NewError("No database open")
	}
	tx, err := b.db.Begin()
	if err != nil {
		return 0, common.NewError("Failed to create transaction", "err", err)
	}
	delStmt := `DELETE FROM Segments WHERE EXISTS (
		SELECT * FROM IntfToSeg WHERE IsdID=? AND AsID=? AND IntfID=?)`
	res, cerr := prepareAndExec(tx, delStmt, intf.IA.I, intf.IA.A, intf.IfID)
	if cerr != nil {
		tx.Rollback()
		return 0, common.NewError("Failed to delete segments", "err", cerr)
	}
	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return 0, common.NewError("Failed to commit transaction", "err", err)
	}
	deleted, _ := res.RowsAffected()
	return int(deleted), nil
}

func (b *Backend) Get(params *query.Params) ([]*query.Result, *common.Error) {
	b.RLock()
	defer b.RUnlock()
	if b.db == nil {
		return nil, common.NewError("No database open")
	}
	stmt := buildQuery(params)
	rows, err := b.db.Query(stmt)
	if err != nil {
		return nil, common.NewError("Error looking up path segment", "q", stmt, "err", err)
	}
	defer rows.Close()
	res := []*query.Result{}
	prevID := -1
	var curRes *query.Result
	for rows.Next() {
		var segRowID int
		var rawSeg sql.RawBytes
		var cfgIsd int
		var cfgAs int
		var cfgID uint64
		err = rows.Scan(&segRowID, &rawSeg, &cfgIsd, &cfgAs, &cfgID)
		if err != nil {
			return nil, common.NewError("Error reading DB response", "err", err)
		}
		// Check if we have a new segment.
		if segRowID != prevID {
			if curRes != nil {
				res = append(res, curRes)
			}
			curRes = &query.Result{}
			var cerr *common.Error
			curRes.Seg, cerr = seg.NewFromRaw(common.RawBytes(rawSeg))
			if cerr != nil {
				return nil, common.NewError("Error unmarshalling segment", "err", cerr)
			}
		}
		// Append cfgID to result
		hpCfgID := &query.HPCfgID{IA: &addr.ISD_AS{I: cfgIsd, A: cfgAs}, ID: cfgID}
		curRes.CfgIDs = append(curRes.CfgIDs, hpCfgID)
		prevID = segRowID
	}
	if curRes != nil {
		res = append(res, curRes)
	}
	return res, nil
}

func buildQuery(params *query.Params) string {
	query := []string{
		"SELECT DISTINCT s.RowID, s.Segment, h.IsdID, h.AsID, h.CfgID FROM Segments s",
		"JOIN HPCfgIds h ON h.SegRowID=s.RowID",
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
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(params.CfgIDs) > 0 {
		subQ := []string{}
		for _, cfgID := range params.CfgIDs {
			subQ = append(subQ, fmt.Sprintf("(h.IsdID='%d' AND h.AsID='%d' AND h.CfgID='%d')",
				cfgID.IA.I, cfgID.IA.A, cfgID.ID))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(params.Intfs) > 0 {
		joins = append(joins, "JOIN IntfToSeg i ON i.SegRowID=s.RowID")
		subQ := []string{}
		for _, spec := range params.Intfs {
			subQ = append(subQ, fmt.Sprintf("(i.IsdID='%d' AND i.AsID='%d' AND i.IntfID='%d')",
				spec.IA.I, spec.IA.A, spec.IfID))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(params.StartsAt) > 0 {
		joins = append(joins, "JOIN StartsAt st ON st.SegRowID=s.RowID")
		subQ := []string{}
		for _, as := range params.StartsAt {
			subQ = append(subQ, fmt.Sprintf("(st.IsdID='%d' AND st.AsID='%d')", as.I, as.A))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(params.EndsAt) > 0 {
		joins = append(joins, "JOIN EndsAt e ON e.SegRowID=s.RowID")
		subQ := []string{}
		for _, as := range params.EndsAt {
			subQ = append(subQ, fmt.Sprintf("(e.IsdID='%d' AND e.AsID='%d')", as.I, as.A))
		}
		where = append(where, strings.Join(subQ, " OR "))
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
