// Copyright 2019 Anapaya Systems
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
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/segment/iface"
	storagebeacon "github.com/scionproto/scion/private/storage/beacon"
	"github.com/scionproto/scion/private/storage/db"
)

var _ beacon.DB = (*Backend)(nil)

type Backend struct {
	db *sql.DB
	*executor
}

// New returns a new SQLite backend opening a database at the given path. If
// no database exists a new database is be created. If the schema version of the
// stored database is different from the one in schema.go, an error is returned.
func New(path string, ia addr.IA) (*Backend, error) {
	db, err := db.NewSqlite(path, Schema, SchemaVersion)
	if err != nil {
		return nil, err
	}
	return &Backend{
		executor: &executor{
			db: db,
			ia: ia,
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

// Close closes the database.
func (b *Backend) Close() error {
	return b.db.Close()
}

type executor struct {
	sync.RWMutex
	db db.Sqler
	ia addr.IA
}

type beaconMeta struct {
	RowID       int64
	InfoTime    time.Time
	LastUpdated time.Time
}

func (e *executor) BeaconSources(ctx context.Context) ([]addr.IA, error) {
	e.RLock()
	defer e.RUnlock()
	query := `SELECT DISTINCT StartIsd, StartAs FROM BEACONS`
	rows, err := e.db.QueryContext(ctx, query)
	if err != nil {
		return nil, db.NewReadError("Error selecting source IAs", err)
	}
	defer rows.Close()
	var ias []addr.IA
	for rows.Next() {
		var isd addr.ISD
		var as addr.AS
		if err := rows.Scan(&isd, &as); err != nil {
			return nil, err
		}
		ia, err := addr.IAFrom(isd, as)
		if err != nil {
			return nil, err
		}
		ias = append(ias, ia)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ias, nil
}

func (e *executor) CandidateBeacons(
	ctx context.Context,
	setSize int,
	usage beacon.Usage,
	src addr.IA,
) ([]beacon.Beacon, error) {

	e.RLock()
	defer e.RUnlock()
	srcCond := ``
	if !src.IsZero() {
		srcCond = `AND StartIsd == ?4 AND StartAs == ?5`
	}
	query := fmt.Sprintf(`
		SELECT b.Beacon, b.InIntfID
		FROM Beacons b
		WHERE ( b.Usage & ?1 ) == ?1 %s
		ORDER BY b.HopsLength ASC
		LIMIT ?2
	`, srcCond)
	rows, err := e.db.QueryContext(ctx, query, usage, setSize, util.TimeToSecs(time.Now()),
		src.ISD(), src.AS())
	if err != nil {
		return nil, db.NewReadError("Error selecting beacons", err)
	}
	defer rows.Close()

	beacons := make([]beacon.Beacon, 0, setSize)
	for rows.Next() {
		var rawBeacon sql.RawBytes
		var inIfID iface.ID
		if err = rows.Scan(&rawBeacon, &inIfID); err != nil {
			return nil, db.NewReadError(beacon.ErrReadingRows, err)
		}
		s, err := beacon.UnpackBeacon(rawBeacon)
		if err != nil {
			return nil, db.NewDataError(beacon.ErrParse, err)
		}
		beacons = append(beacons, beacon.Beacon{Segment: s, InIfID: uint16(inIfID)})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return beacons, nil
}

// InsertBeacon inserts the beacon if it is new or updates the changed
// information.
func (e *executor) InsertBeacon(
	ctx context.Context,
	b beacon.Beacon,
	usage beacon.Usage,
) (beacon.InsertStats, error) {

	ret := beacon.InsertStats{}
	// Compute ids outside of the lock.
	segID := b.Segment.ID()

	e.Lock()
	defer e.Unlock()
	meta, err := e.getBeaconMeta(ctx, segID)
	if err != nil {
		return ret, err
	}
	if meta != nil {
		// Update the beacon data if it is newer.
		if b.Segment.Info.Timestamp.After(meta.InfoTime) {
			if err := e.updateExistingBeacon(ctx, b, usage, meta.RowID, time.Now()); err != nil {
				return ret, err
			}
			ret.Updated = 1
			return ret, nil
		}
		return ret, nil
	}
	// Insert new beacon.
	err = db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		return insertNewBeacon(ctx, tx, b, usage, time.Now())
	})
	if err != nil {
		return ret, err
	}

	ret.Inserted = 1
	return ret, nil

}

func (e *executor) GetBeacons(
	ctx context.Context,
	params *storagebeacon.QueryParams,
) ([]storagebeacon.Beacon, error) {

	e.RLock()
	defer e.RUnlock()
	stmt, args := e.buildQuery(params)
	rows, err := e.db.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, serrors.Wrap("looking up beacons", err, "query", stmt)
	}
	defer rows.Close()
	var res []storagebeacon.Beacon
	for rows.Next() {
		var RowID int
		var lastUpdated int64
		var usage int
		var rawBeacon sql.RawBytes
		var InIfID uint16
		err = rows.Scan(&RowID, &lastUpdated, &usage, &rawBeacon, &InIfID)
		if err != nil {
			return nil, serrors.Wrap("reading row", err)
		}
		seg, err := beacon.UnpackBeacon(rawBeacon)
		if err != nil {
			return nil, serrors.Wrap("parsing beacon", err)
		}
		res = append(res, storagebeacon.Beacon{
			Beacon: beacon.Beacon{
				Segment: seg,
				InIfID:  InIfID,
			},
			Usage:       beacon.Usage(usage),
			LastUpdated: time.Unix(0, lastUpdated),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

func (e *executor) DeleteBeacon(ctx context.Context, partialID string) error {
	_, err := e.deleteInTx(ctx, func(tx *sql.Tx) (sql.Result, error) {
		delStmt := `DELETE FROM Beacons WHERE hex(SegID) LIKE ?`
		return tx.ExecContext(ctx, delStmt, partialID+"%")
	})
	return err
}

func (e *executor) buildQuery(params *storagebeacon.QueryParams) (string, []any) {
	var args []any
	query := "SELECT DISTINCT RowID, LastUpdated, Usage, Beacon, InIntfID FROM Beacons"
	if params == nil {
		return query, args
	}
	where := []string{}
	if len(params.SegIDs) > 0 {
		subQ := make([]string, 0, len(params.SegIDs))
		for _, segID := range params.SegIDs {
			subQ = append(subQ, "hex(SegID) LIKE (hex(?) || '%')")
			args = append(args, segID)
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}
	if len(params.StartsAt) > 0 {
		subQ := []string{}
		for _, as := range params.StartsAt {
			switch {
			case as.IsZero():
				continue
			case as.ISD() == 0:
				subQ = append(subQ, "StartAs=?")
				args = append(args, as.AS())
			case as.AS() == 0:
				subQ = append(subQ, "StartIsd=?")
				args = append(args, as.ISD())
			case as.ISD() != 0 && as.AS() != 0:
				subQ = append(subQ, "(StartIsd=? AND StartAs=?)")
				args = append(args, as.ISD(), as.AS())
			}
		}
		if len(subQ) > 0 {
			where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
		}
	}
	if len(params.IngressInterfaces) > 0 {
		subQ := make([]string, 0, len(params.IngressInterfaces))
		for _, intf := range params.IngressInterfaces {
			subQ = append(subQ, "InIntfID=?")
			args = append(args, intf)
		}
		where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
	}

	if len(params.Usages) > 0 {
		subQ := []string{}
		for _, u := range params.Usages {
			if u > 0 {
				subQ = append(subQ, "(Usage & ? = ?)")
				args = append(args, int64(u), int64(u))
			}
		}
		if len(subQ) > 0 {
			where = append(where, fmt.Sprintf("(%s)", strings.Join(subQ, " OR ")))
		}
	}

	if !params.ValidAt.IsZero() {
		where = append(where, "(InfoTime <= ? AND ? <= ExpirationTime)")
		args = append(args, params.ValidAt.Unix())
		args = append(args, params.ValidAt.Unix())
	}
	// Assemble the query.
	if len(where) > 0 {
		query += "\n" + fmt.Sprintf("WHERE %s", strings.Join(where, " AND\n"))
	}
	query += "\n" + "ORDER BY LastUpdated DESC"
	return query, args
}

// getBeaconMeta gets the metadata for existing beacons.
func (e *executor) getBeaconMeta(ctx context.Context, segID []byte) (*beaconMeta, error) {
	var rowID, infoTime, lastUpdated int64
	query := "SELECT RowID, InfoTime, LastUpdated FROM Beacons WHERE SegID=?"
	err := e.db.QueryRowContext(ctx, query, segID).Scan(&rowID, &infoTime, &lastUpdated)
	// New beacons are not in the table.
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, db.NewReadError("Failed to lookup beacon", err)
	}
	meta := &beaconMeta{
		RowID:       rowID,
		InfoTime:    time.Unix(infoTime, 0),
		LastUpdated: time.Unix(0, lastUpdated),
	}
	return meta, nil
}

// updateExistingBeacon updates the changeable data for an existing beacon.
func (e *executor) updateExistingBeacon(
	ctx context.Context,
	b beacon.Beacon,
	usage beacon.Usage,
	rowID int64,
	now time.Time,
) error {

	fullID := b.Segment.FullID()
	packedSeg, err := beacon.PackBeacon(b.Segment)
	if err != nil {
		return err
	}
	infoTime := b.Segment.Info.Timestamp.Unix()
	lastUpdated := now.UnixNano()
	expTime := b.Segment.MaxExpiry().Unix()
	inst := `UPDATE Beacons SET FullID=?, InIntfID=?, HopsLength=?, InfoTime=?,
			ExpirationTime=?, LastUpdated=?, Usage=?, Beacon=?
			WHERE RowID=?`
	_, err = e.db.ExecContext(ctx, inst, fullID, b.InIfID, len(b.Segment.ASEntries), infoTime,
		expTime, lastUpdated, usage, packedSeg, rowID)
	if err != nil {
		return db.NewWriteError("update segment", err)
	}
	return nil
}

func insertNewBeacon(
	ctx context.Context,
	tx *sql.Tx,
	b beacon.Beacon,
	usage beacon.Usage,
	now time.Time,
) error {

	segID := b.Segment.ID()
	fullID := b.Segment.FullID()
	packed, err := beacon.PackBeacon(b.Segment)
	if err != nil {
		return db.NewInputDataError("pack segment", err)
	}
	start := b.Segment.FirstIA()
	infoTime := b.Segment.Info.Timestamp.Unix()
	lastUpdated := now.UnixNano()
	expTime := b.Segment.MaxExpiry().Unix()

	// Insert beacon.
	inst := `
	INSERT INTO Beacons (SegID, FullID, StartIsd, StartAs, InIntfID, HopsLength, InfoTime,
		ExpirationTime, LastUpdated, Usage, Beacon)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err = tx.ExecContext(ctx, inst, segID, fullID, start.ISD(), start.AS(), b.InIfID,
		len(b.Segment.ASEntries), infoTime, expTime, lastUpdated, usage, packed)
	if err != nil {
		return db.NewWriteError("insert beacon", err)
	}
	return nil
}

func (e *executor) DeleteExpiredBeacons(ctx context.Context, now time.Time) (int, error) {
	return e.deleteInTx(ctx, func(tx *sql.Tx) (sql.Result, error) {
		delStmt := `DELETE FROM Beacons WHERE ExpirationTime < ?`
		return tx.ExecContext(ctx, delStmt, now.Unix())
	})
}

func (e *executor) deleteInTx(
	ctx context.Context,
	delFunc func(tx *sql.Tx) (sql.Result, error),
) (int, error) {

	e.Lock()
	defer e.Unlock()
	return db.DeleteInTx(ctx, e.db, delFunc)
}
