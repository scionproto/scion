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

	"github.com/netsec-ethz/scion/go/lib/addr"

	_ "github.com/mattn/go-sqlite3"

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
// no database exists or if the schema version of the existing database is smaller
// than the schema version in schema.go, a new database is be created. If the
// schema version of the stored database is larger than the one in schema.go, an
// error is returned.
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
	if version > SchemaVersion {
		return nil, common.NewError("The database schema version is newer than supported")
	}
	if version < SchemaVersion {
		if cerr := b.setup(); cerr != nil {
			return nil, cerr
		}
	}
	return b, nil
}

func (b *Backend) open(path string) *common.Error {
	b.Lock()
	defer b.Unlock()
	// Add foreign_key parameter to path to enable foreign key support.
	uri := fmt.Sprintf("%s?_foreign_keys=1", path)
	var err error
	b.db, err = sql.Open("sqlite3", uri)
	if err != nil {
		return common.NewError("Couldn't open SQLite database", "err", err)
	}
	// Ensure foreign keys are supported and enabled.
	var enabled bool
	err = b.db.QueryRow("PRAGMA foreign_keys;").Scan(&enabled)
	if err != nil {
		return common.NewError("Foreign keys not supported", "err", err)
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

func (b *Backend) updateExisting(meta *segMeta,
	segTypes []seg.Type, cfgIDs []*query.HPCfgID) *common.Error {
	tx, err := b.db.Begin()
	if err != nil {
		return common.NewError("Failed to create transaction", "err", err)
	}
	// Update segment.
	if cerr := updateSeg(tx, meta); err != nil {
		tx.Rollback()
		return cerr
	}
	// Check if the existing segment is registered as the given type(s).
	for _, segType := range segTypes {
		ok, cerr := b.checkType(meta.RowID, segType)
		if err != nil {
			tx.Rollback()
			return cerr
		}
		if !ok {
			if cerr = insertType(tx, meta.RowID, segType); cerr != nil {
				tx.Rollback()
				return cerr
			}
		}
	}
	// Check if the existing segment is registered with the given cfgIDs.
	for _, cfgID := range cfgIDs {
		ok, cerr := b.checkCfgID(meta.RowID, cfgID)
		if cerr != nil {
			tx.Rollback()
			return cerr
		}
		if !ok {
			if cerr = insertCfgID(tx, meta.RowID, cfgID); cerr != nil {
				tx.Rollback()
				return cerr
			}
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
	stmtStr := `UPDATE Segments SET LastUpdated=?, Segment=? WHERE ID=?`
	_, err := prepareAndExec(tx, stmtStr, meta.LastUpdated.Unix(), packedSeg, meta.RowID)
	if err != nil {
		return common.NewError("Failed to update segment", "err", err)
	}
	return nil
}

func (b *Backend) checkType(rowID int64, segType seg.Type) (bool, *common.Error) {
	rows, err := b.db.Query("SELECT Type FROM SegTypes WHERE SegID=?", rowID)
	if err != nil {
		return false, common.NewError("CheckType: Failed to execute query", "err", err)
	}
	defer rows.Close()
	for rows.Next() {
		var storedType uint8
		err = rows.Scan(&storedType)
		if err != nil {
			return false, common.NewError("CheckType: Failed to extract data", "err", err)
		}
		if seg.Type(storedType) == segType {
			return true, nil
		}
	}
	return false, nil
}

func (b *Backend) checkCfgID(rowID int64, cfgID *query.HPCfgID) (bool, *common.Error) {
	rows, err := b.db.Query("SELECT IsdID, AsID, CfgID FROM HPCfgIds WHERE SegID=?", rowID)
	if err != nil {
		return false, common.NewError("CheckCfgID: Failed to execute query", "err", err)
	}
	defer rows.Close()
	for rows.Next() {
		var isd int
		var as int
		var ID uint64
		err = rows.Scan(&isd, &as, &ID)
		if err != nil {
			return false, common.NewError("CheckCfgID: Failed to extract data", "err", err)
		}
		if cfgID.Eq(query.NewHPCfgID(isd, as, ID)) {
			return true, nil
		}
	}
	return false, nil
}

func insertInterfaces(tx *sql.Tx, ases []*seg.ASEntry, rowID int64) *common.Error {
	for _, as := range ases {
		ia := as.IA()
		stmtStr := `INSERT INTO IntfToSeg (IsdID, ASID, IntfID, SegID) VALUES (?, ?, ?, ?)`
		stmt, err := tx.Prepare(stmtStr)
		if err != nil {
			return common.NewError("Failed to prepare statement", "err", err)
		}
		defer stmt.Close()
		for _, hop := range as.HopEntries {
			if hop.InIF != 0 {
				_, err := stmt.Exec(ia.I, ia.A, hop.InIF, rowID)
				if err != nil {
					return common.NewError("Failed to insert into IntfToSeg", "err", err)
				}
			}
			if hop.OutIF != 0 {
				_, err = stmt.Exec(ia.I, ia.A, hop.OutIF, rowID)
				if err != nil {
					return common.NewError("Failed to insert into IntfToSeg", "err", err)
				}
			}
		}
	}
	return nil
}

func insertStartOrEnd(tx *sql.Tx, as *seg.ASEntry,
	rowID int64, tableName string) *common.Error {
	ia := as.IA()
	stmtStr := fmt.Sprintf("INSERT INTO %s (IsdID, AsID, SegID) VALUES (?, ?, ?)", tableName)
	_, err := prepareAndExec(tx, stmtStr, ia.I, ia.A, rowID)
	if err != nil {
		return common.NewError(fmt.Sprintf("Faild to insert into %s", tableName), "err", err)
	}
	return nil
}

func insertType(tx *sql.Tx, rowID int64, segType seg.Type) *common.Error {
	_, err := prepareAndExec(tx, "INSERT INTO SegTypes (SegID, Type) VALUES (?, ?)", rowID, segType)
	if err != nil {
		return common.NewError("Faild to insert type", "err", err)
	}
	return nil
}

func insertCfgID(tx *sql.Tx, rowID int64, cfgID *query.HPCfgID) *common.Error {
	_, err := prepareAndExec(
		tx, "INSERT INTO HPCfgIds (SegID, IsdID, AsID, CfgID) VALUES (?, ?, ?, ?)",
		rowID, cfgID.IA.I, cfgID.IA.A, cfgID.ID)
	if err != nil {
		return common.NewError("Faild to insert cfgID", "err", err)
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
	if err != nil {
		tx.Rollback()
		return common.NewError("Failed to insert path segment", "err", err)
	}
	rowID, err := res.LastInsertId()
	if err != nil {
		tx.Rollback()
		return common.NewError("Failed to retrieve rowID of inserted segment", "err", err)
	}
	// Insert all interfaces.
	cerr = insertInterfaces(tx, pseg.ASEntries, rowID)
	if cerr != nil {
		tx.Rollback()
		return cerr
	}
	// Insert ISD-AS to StartsAt.
	cerr = insertStartOrEnd(tx, pseg.ASEntries[0], rowID, "StartsAt")
	if cerr != nil {
		tx.Rollback()
		return cerr
	}
	// Insert ISD-AS to EndsAt.
	cerr = insertStartOrEnd(tx, pseg.ASEntries[len(pseg.ASEntries)-1], rowID, "EndsAt")
	if cerr != nil {
		tx.Rollback()
		return cerr
	}
	// Insert segType information.
	for _, segType := range segTypes {
		cerr = insertType(tx, rowID, segType)
		if cerr != nil {
			tx.Rollback()
			return cerr
		}
	}
	// Insert cfgID information.
	for _, cfgID := range cfgIDs {
		cerr = insertCfgID(tx, rowID, cfgID)
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

func (b *Backend) Insert(pseg *seg.PathSegment, segTypes []seg.Type) (int, *common.Error) {
	return b.InsertWithCfgIDs(pseg, segTypes, []*query.HPCfgID{&query.NullCfgID})
}

func (b *Backend) InsertWithCfgIDs(pseg *seg.PathSegment,
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
	if err != nil {
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
	if err != nil {
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

func buildQuery(params *query.Params) string {
	query := []string{
		"SELECT DISTINCT s.ID, s.Segment, h.IsdID, h.AsID, h.CfgID FROM Segments s",
		"JOIN HPCfgIds h ON h.SegID=s.ID",
	}
	if params == nil {
		return strings.Join(query, "\n")
	}
	joins := []string{}
	where := []string{}
	if len(params.SegID) > 0 {
		where = append(where, fmt.Sprintf("s.SegID=x'%v'", params.SegID))
	}
	if len(params.SegTypes) > 0 {
		joins = append(joins, "JOIN SegTypes t ON t.SegID=s.ID")
		subQ := []string{}
		for _, segType := range params.SegTypes {
			subQ = append(subQ, fmt.Sprintf("t.Type='%d'", segType))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(params.CfgIDs) > 0 {
		subQ := []string{}
		for _, cfgID := range params.CfgIDs {
			subQ = append(subQ, fmt.Sprintf("(h.IsdID='%v' AND h.AsID='%v' AND h.CfgID='%v')",
				cfgID.IA.I, cfgID.IA.A, cfgID.ID))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(params.Intfs) > 0 {
		joins = append(joins, "JOIN IntfToSeg i ON i.SegID=s.ID")
		subQ := []string{}
		for _, spec := range params.Intfs {
			subQ = append(subQ, fmt.Sprintf("(i.IsdID='%v' AND i.AsID='%v' AND i.IntfID='%v')",
				spec.IA.I, spec.IA.A, spec.IfID))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(params.StartsAt) > 0 {
		joins = append(joins, "JOIN StartsAt st ON st.SegID=s.ID")
		subQ := []string{}
		for _, as := range params.StartsAt {
			subQ = append(subQ, fmt.Sprintf("(st.IsdID='%v' AND st.AsID='%v')", as.I, as.A))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(params.EndsAt) > 0 {
		joins = append(joins, "JOIN EndsAt e ON e.SegID=s.ID")
		subQ := []string{}
		for _, as := range params.EndsAt {
			subQ = append(subQ, fmt.Sprintf("(e.IsdID='%v' AND e.AsID='%v')", as.I, as.A))
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
		var rowID int
		var rawSeg sql.RawBytes
		var cfgIsd int
		var cfgAs int
		var cfgID uint64
		err = rows.Scan(&rowID, &rawSeg, &cfgIsd, &cfgAs, &cfgID)
		if err != nil {
			return nil, common.NewError("Error reading DB response", "err", err)
		}
		// Check if we have a new segment.
		if rowID != prevID {
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
		prevID = rowID
	}
	if curRes != nil {
		res = append(res, curRes)
	}
	return res, nil
}
