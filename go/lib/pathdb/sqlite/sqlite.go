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
	"sync"
	"database/sql"
	"fmt"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl/seg"
	"github.com/netsec-ethz/scion/go/lib/pathdb/conn"
)

const (
	setupStmt = `CREATE TABLE Segments(
		ID INTEGER PRIMARY KEY ,
		SegID DATA UNIQUE NOT NULL,
		LastUpdated INTEGER NOT NULL,
		Segment DATA NOT NULL
	);
	CREATE TABLE IntfToSeg(
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		IntfID INTEGER NOT NULL,
		SegID INTEGER NOT NULL,
		FOREIGN KEY (SegID) REFERENCES Segments(ID)
	);
	CREATE TABLE StartsAt(
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		SegID INTEGER NOT NULL,
		FOREIGN KEY (SegID) REFERENCES Segments(ID)
	);
	CREATE TABLE EndsAt(
		IsdID INTEGER NOT NULL,
		AsID INTEGER NOT NULL,
		SegID INTEGER NOT NULL,
		FOREIGN KEY (SegID) REFERENCES Segments(ID)
	);
	CREATE TABLE SegTypes(
		SegID INTEGER UNIQUE NOT NULL,
		Type INTEGER NOT NULL,
		FOREIGN KEY (SegID) REFERENCES Segments(ID)
	);
	CREATE TABLE SegLabels(
		SegID INTEGER UNIQUE NOT NULL,
		Label INTEGER NOT NULL,
		FOREIGN KEY (SegID) REFERENCES Segments(ID)
	);`
)

type segMeta struct {
	RowID       int
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
	var err error
	b.db, err = sql.Open("sqlite3", path)
	if err != nil {
		return common.NewError("Couldn't open SQLite database", "err", err)
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

func (b *Backend) updateExisting(meta *segMeta, segTypes []uint8, label uint64) *common.Error {
	segID := meta.SegID
	err, tx := b.db.Begin()
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
		ok, cerr := b.checkType(segID, segType)
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
	// Check if the existing segment is registered with the given label.
	if label != 0 {
		ok, cerr := b.checkLabel(segID, label)
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
	if cerr != nil {
		return common.NewError("Failed to commit transaction", "err", err)
	}
	return nil
}

func updateSeg(tx *sql.Tx, meta *segMeta) *common.Error {
	packedSeg, cerr := meta.Seg.Pack()
	if cerr != nil {
		return cerr
	}
	stmtStr := `UPDATE Segments SET LastUpdated=?, Segment=? WHERE ID=?;`
	_, err := tx.Exec(stmtStr, meta.LastUpdated.Unix(), packedSeg, meta.RowID)
	if err != nil {
		return common.NewError("Failed to update segment", "err", err)
	}
	return nil
}

func (b *Backend) checkType(segID common.RawBytes, segType uint8) (bool, error) {
	rows, err := b.db.Query("SELECT Type FROM SegTypes WHERE SegID=?;", segID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var storedType uint8
		err = rows.Scan(&storedType)
		if err != nil {
			return false, err
		}
		if storedType == segType {
			return true, nil
		}
	}
	return false, nil
}

func (b *Backend) checkLabel(segID common.RawBytes, label uint64) (bool, error) {
	rows, err := b.db.Query("SELECT Label FROM SegLabels WHERE SegID=?;", segID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var storedLabel uint64
		err = rows.Scan(&storedLabel)
		if err != nil {
			return false, err
		}
		if storedLabel == label {
			return true, nil
		}
	}
	return false, nil
}

func insertInterfaces(tx *sql.Tx, ases []*seg.ASEntry, rowID int64) *common.Error {
	for _, as := range ases {
		ia := as.IA()
		stmtStr := `INSERT INTO IntfToSeg (IsdID, ASID, IntfID, SegID VALUES (?, ?, ?, ?);`
		stmt, err := tx.Prepare(stmtStr)
		if err != nil {
			return common.NewError("Failed to prepare statement", "err", err)
		}
		defer stmt.Close()
		for _, hop := range as.HopEntries {
			_, err := stmt.Exec(ia.I, ia.A, hop.InIF, rowID)
			if err != nil {
				return common.NewError("Failed to insert into IntfToSeg", "err", err)
			}
			_, err = stmt.Exec(ia.I, ia.A, hop.OutIF, rowID)
			if err != nil {
				return common.NewError("Failed to insert into IntfToSeg", "err", err)
			}
		}
	}
	return nil
}

func insertStartOrEnd(tx *sql.Tx, as *seg.ASEntry,
	rowID int64, tableName string) *common.Error {
	ia := as.IA()
	stmtStr := fmt.Sprintf("INSERT INTO %s (IsdID, AsID, SegID) VALUES (?, ?, ?);", tableName)
	_, err := tx.Exec(stmtStr, ia.I, ia.A, rowID)
	if err != nil {
		return common.NewError(fmt.Sprintf("Faild to insert into %s", tableName), "err", err)
	}
	return nil
}

func insertType(tx *sql.Tx, rowID int64, segType uint8) error {
	_, err := tx.Exec("INSERT INTO SegTypes (SegID, Type) VALUES (?, ?);", rowID, segType)
	if err != nil {
		return err
	}
	return nil
}

func insertLabel(tx *sql.Tx, rowID int64, label uint64) error {
	_, err := tx.Exec("INSERT INTO SegLabels (SegID, Label) VALUES (?, ?);", rowID, label)
	if err != nil {
		return err
	}
	return nil
}

func (b *Backend) insertFull(pseg *seg.PathSegment, segTypes []uint8, label uint64) *common.Error {
	tx, err := b.db.Begin()
	if err != nil {
		return common.NewError("Failed to create transaction", "err", err)
	}
	segID := pseg.ID()
	packedSeg, cerr := pseg.Pack()
	if err != nil {
		return cerr
	}
	// Insert path segment.
	stmt := `INSERT INTO Segments (SegID, LastUpdated, Segment) VALUES (?, ?, ?);`
	res, err := tx.Exec(stmt, segID, time.Now().Unix(), packedSeg)
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
	cerr = b.insertInterfaces(tx, pseg.ASEntries, rowID)
	if cerr != nil {
		tx.Rollback()
		return cerr
	}
	// Insert ISD-AS to StartsAt.
	cerr = b.insertStartOrEnd(tx, pseg.ASEntries[0], rowID, "StartsAt")
	if cerr != nil {
		tx.Rollback()
		return cerr
	}
	// Insert ISD-AS to EndsAt.
	cerr = b.insertStartOrEnd(tx, pseg.ASEntries[len(pseg.ASEntries)-1], rowID, "EndsAt")
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
	cerr = insertLabel(tx, rowID, label)
	if cerr != nil {
		tx.Rollback()
		return cerr
	}
	// Commit transaction
	err = tx.Commit()
	if cerr != nil {
		return common.NewError("Failed to commit transaction", "err", err)
	}
	return nil
}

func (b *Backend) Insert(pseg *seg.PathSegment, segTypes []uint8) (int, *common.Error) {
	return b.InsertWithLabel(pseg, segTypes, 0)
}

func (b *Backend) InsertWithLabel(pseg *seg.PathSegment,
	segTypes []uint8, label uint64) (int, *common.Error) {
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
			if err := b.updateExisting(meta, segTypes, label); err != nil {
				return 0, err
			}
			return 1, nil
		}
		return 0, nil
	}
	// Do full insert.
	err = b.insertFull(pseg, segTypes, label)
	if err != nil {
		return 0, err
	}
	return 1, nil
}

func (b *Backend) get(segID common.RawBytes) (*segMeta, *common.Error) {
	rows, err := b.db.Query("SELECT * FROM Segments WHERE SegID=?;", segID)
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
		meta.Seg, cerr = seg.NewPathSegmentFromRaw(common.RawBytes(rawSeg))
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
        return nil, common.NewError("No database open")
    }
    res, err := b.db.Query("DELETE FROM Segments WHERE SegID=?;", segID)
    if err != nil {
        return 0, common.NewError("Failed to delete segment", "err", err)
    }
    deleted, _ := res.RowsAffected()
    return deleted, nil
}

func (b* Backend) DeleteWithIntf(ia *addr.ISD_AS, ifID uint64) (int, *common.Error) {
    b.Lock()
    defer b.Unlock()
    if b.db == nil {
        return nil, common.NewError("No database open")
    }
    // TODO(shitz): Implement
    return 0, nil
}

func (b *Backend) Get(opt *conn.QueryOptions) ([]*seg.PathSegment, *common.Error) {
	b.RLock()
	defer b.RUnlock()
	if b.db == nil {
		return nil, common.NewError("No database open")
	}
	query := buildQuery(opt)
	log.Debug("Query: %s", query)
	rows, err := b.db.Query(query)
	if err != nil {
		return nil, common.NewError("Error looking up path segment", "q", query, "err", err)
	}
	defer rows.Close()
	res := []*seg.PathSegment{}
	for rows.Next() {
		var rowID int64
		var rawSeg sql.RawBytes
		err = rows.Scan(&rowID, &rawSeg)
		if err != nil {
			return []*seg.PathSegment{}, common.NewError("Error reading DB response", "err", err)
		}
		seg, cerr := seg.NewPathSegmentFromRaw(common.RawBytes(rawSeg))
		if cerr != nil {
			return []*seg.PathSegment{}, common.NewError("Error unmarshalling segment", "err", cerr)
		}
		res = append(res, seg)
	}
	return res, nil
}

func buildQuery(opt *conn.QueryOptions) string {
	query := []string{"SELECT s.ID, s.Segment FROM Segments s"}
	if opt == nil {
		return query[0] + ";"
	}
	joins := []string{}
	where := []string{}
	if len(opt.SegID) > 0 {
		where = append(where, fmt.Sprintf("s.SegID=%v", opt.SegID))
	}
	if len(opt.SegTypes) > 0 {
		joins = append(joins, "JOIN SegTypes t ON t.SegID=s.ID")
		subQ := []string{}
		for _, segType := range opt.SegTypes {
			subQ = append(subQ, fmt.Sprintf("t.Type=%v", segType))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(opt.Labels) > 0 {
		joins = append(joins, "JOIN SegLabels l ON l.SegID=s.ID")
		subQ := []string{}
		for _, label := range opt.Labels {
			subQ = append(subQ, fmt.Sprintf("l.Label=%v", label))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(opt.Intfs) > 0 {
		joins = append(joins, "JOIN IntfToSeg i ON i.SegID=s.ID")
		subQ = []string{}
		for i, spec := range opt.Intfs {
			subQ = append(subQ, fmt.Sprintf("(i.IsdID=%v AND i.AsID=%v AND i.IntfID=%v)",
				spec.IA.I, spec.IA.A, spec.IfID))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(opt.StartsAt) > 0 {
		joins = append(joins, "JOIN StartsAt st ON st.SegID=s.ID")
		subQ = []string{}
		for _, as := range opt.StartsAt {
			subQ = append(subQ, fmt.Sprintf("(st.IsdID=%v AND st.AsID=%v)", as.I, as.A))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	if len(opt.EndsAt) > 0 {
		joins = append(joins, "JOIN EndsAt e ON e.SegID=s.ID")
		subQ = []string{}
		for _, as := range opt.EndsAt {
			subQ = append(subQ, fmt.Sprintf("(e.IsdID=%v AND e.AsID=%v)", as.I, as.A))
		}
		where = append(where, strings.Join(subQ, " OR "))
	}
	// Assemble the query.
	if len(joins) > 0 {
		query = append(query, strings.Join(joins, "\n"))
	}
	if len(where) > 0 {
		query = append(query, fmt.Sprintf("WHERE %s", strings.Join(whereStr, "AND\n"))
	}
	return strings.Join(query, "\n") + ";"
}
