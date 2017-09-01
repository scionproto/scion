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
	"bytes"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	_ "github.com/mattn/go-sqlite3"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl/seg"
	"github.com/netsec-ethz/scion/go/lib/pathdb/conn"
	"github.com/netsec-ethz/scion/go/lib/pathdb/query"
)

const (
	setupStmt = `CREATE TABLE Segments(
		ID INTEGER PRIMARY KEY AUTOINCREMENT,
		SegID DATA UNIQUE NOT NULL,
		LastUpdated INTEGER NOT NULL,
		Segment DATA NOT NULL
	);
	CREATE TABLE IntfToSeg(
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		IntfID INTEGER NOT NULL,
		SegID INTEGER NOT NULL,
		PRIMARY KEY (IsdID, AsID, IntfID, SegID) ON CONFLICT IGNORE,
		FOREIGN KEY (SegID) REFERENCES Segments(ID) ON DELETE CASCADE
	);
	CREATE TABLE StartsAt(
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		SegID INTEGER NOT NULL,
		FOREIGN KEY (SegID) REFERENCES Segments(ID) ON DELETE CASCADE
	);
	CREATE TABLE EndsAt(
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		SegID INTEGER NOT NULL,
		FOREIGN KEY (SegID) REFERENCES Segments(ID) ON DELETE CASCADE
	);
	CREATE TABLE SegTypes(
		SegID INTEGER NOT NULL,
		Type INTEGER NOT NULL,
		FOREIGN KEY (SegID) REFERENCES Segments(ID) ON DELETE CASCADE
	);
	CREATE TABLE SegLabels(
		SegID INTEGER NOT NULL,
		Label DATA NOT NULL,
		FOREIGN KEY (SegID) REFERENCES Segments(ID) ON DELETE CASCADE
	);`
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

func New(path string) (*Backend, *common.Error) {
	b := &Backend{}
	if err := b.open(path); err != nil {
		return nil, err
	}
	if err := b.setup(); err != nil {
		return nil, err
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
	// TODO(shitz): Add check whether DB is already setup.
	_, err := b.db.Exec(setupStmt)
	if err != nil {
		return common.NewError("Failed to set up SQLite database", "err", err)
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
	segTypes []uint8, labels []query.SegLabel) *common.Error {
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
	// Check if the existing segment is registered with the given labels.
	for _, label := range labels {
		ok, cerr := b.checkLabel(meta.RowID, label)
		if cerr != nil {
			tx.Rollback()
			return cerr
		}
		if !ok {
			if cerr = insertLabel(tx, meta.RowID, label); cerr != nil {
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

func (b *Backend) checkType(rowID int64, segType uint8) (bool, *common.Error) {
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
		if storedType == segType {
			return true, nil
		}
	}
	return false, nil
}

func (b *Backend) checkLabel(rowID int64, label query.SegLabel) (bool, *common.Error) {
	rows, err := b.db.Query("SELECT Label FROM SegLabels WHERE SegID=?;", rowID)
	if err != nil {
		return false, common.NewError("CheckLabel: Failed to execute query", "err", err)
	}
	defer rows.Close()
	for rows.Next() {
		var storedLabel sql.RawBytes
		err = rows.Scan(&storedLabel)
		if err != nil {
			return false, common.NewError("CheckLabel: Failed to extract data", "err", err)
		}
		if bytes.Compare(storedLabel, label) == 0 {
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

func insertType(tx *sql.Tx, rowID int64, segType uint8) *common.Error {
	_, err := prepareAndExec(tx, "INSERT INTO SegTypes (SegID, Type) VALUES (?, ?)", rowID, segType)
	if err != nil {
		return common.NewError("Faild to insert type", "err", err)
	}
	return nil
}

func insertLabel(tx *sql.Tx, rowID int64, label query.SegLabel) *common.Error {
	_, err := prepareAndExec(tx, "INSERT INTO SegLabels (SegID, Label) VALUES (?, ?)", rowID, label)
	if err != nil {
		return common.NewError("Faild to insert label", "err", err)
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
	segTypes []uint8, labels []query.SegLabel) *common.Error {
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
	// Insert label information.
	for _, label := range labels {
		cerr = insertLabel(tx, rowID, label)
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

func (b *Backend) Insert(pseg *seg.PathSegment, segTypes []uint8) (int, *common.Error) {
	return b.InsertWithLabels(pseg, segTypes, []query.SegLabel{query.NullLabel})
}

func (b *Backend) InsertWithLabels(pseg *seg.PathSegment,
	segTypes []uint8, labels []query.SegLabel) (int, *common.Error) {
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
			if err := b.updateExisting(meta, segTypes, labels); err != nil {
				return 0, err
			}
			return 1, nil
		}
		return 0, nil
	}
	// Do full insert.
	err = b.insertFull(pseg, segTypes, labels)
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
	res, cerr := prepareAndExec(tx, "DELETE FROM Segments WHERE SegID=?;", segID)
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
		SELECT * FROM IntfToSeg WHERE IsdID=? AND AsID=? AND IntfID=?
	);`
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

func (b *Backend) Get(opt *query.Params) ([]*query.Result, *common.Error) {
	b.RLock()
	defer b.RUnlock()
	if b.db == nil {
		return nil, common.NewError("No database open")
	}
	stmt := buildQuery(opt)
	log.Debug("Query", "str", stmt)
	rows, err := b.db.Query(stmt)
	if err != nil {
		return nil, common.NewError("Error looking up path segment", "q", stmt, "err", err)
	}
	defer rows.Close()
	res := []*query.Result{}
	prevID := int64(-1)
	var curRes *query.Result
	for rows.Next() {
		var rowID int64
		var rawSeg sql.RawBytes
		var rawLabel sql.RawBytes
		err = rows.Scan(&rowID, &rawSeg, &rawLabel)
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
		// Append label to result
		curRes.Labels = append(curRes.Labels, query.SegLabel(rawLabel))
		prevID = rowID
	}
	if curRes != nil {
		res = append(res, curRes)
	}
	return res, nil
}

func buildQuery(opt *query.Params) string {
	query := []string{
		"SELECT DISTINCT s.ID, s.Segment, l.Label FROM Segments s",
		"JOIN SegLabels l ON l.SegID=s.ID",
	}
	if opt == nil {
		return strings.Join(query, "\n")
	}
	joins := []string{}
	where := []string{}
	if len(opt.SegID) > 0 {
		where = append(where, fmt.Sprintf("s.SegID=x'%v'", opt.SegID))
	}
	if len(opt.SegTypes) > 0 {
		joins = append(joins, "JOIN SegTypes t ON t.SegID=s.ID")
		subQ := []string{}
		for _, segType := range opt.SegTypes {
			subQ = append(subQ, fmt.Sprintf("t.Type='%v'", segType))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(opt.Labels) > 0 {
		subQ := []string{}
		for _, label := range opt.Labels {
			subQ = append(subQ, fmt.Sprintf("l.Label=x'%v'", label))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(opt.Intfs) > 0 {
		joins = append(joins, "JOIN IntfToSeg i ON i.SegID=s.ID")
		subQ := []string{}
		for _, spec := range opt.Intfs {
			subQ = append(subQ, fmt.Sprintf("(i.IsdID='%v' AND i.AsID='%v' AND i.IntfID='%v')",
				spec.IA.I, spec.IA.A, spec.IfID))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(opt.StartsAt) > 0 {
		joins = append(joins, "JOIN StartsAt st ON st.SegID=s.ID")
		subQ := []string{}
		for _, as := range opt.StartsAt {
			subQ = append(subQ, fmt.Sprintf("(st.IsdID='%v' AND st.AsID='%v')", as.I, as.A))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(opt.EndsAt) > 0 {
		joins = append(joins, "JOIN EndsAt e ON e.SegID=s.ID")
		subQ := []string{}
		for _, as := range opt.EndsAt {
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
