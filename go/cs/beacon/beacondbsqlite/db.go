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

package beacondbsqlite

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/util"
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

// BeginTransaction begins a transaction on the database.
func (b *Backend) BeginTransaction(ctx context.Context,
	opts *sql.TxOptions) (beacon.Transaction, error) {

	b.Lock()
	defer b.Unlock()
	tx, err := b.db.BeginTx(ctx, opts)
	if err != nil {
		return nil, db.NewTxError("create tx", err)
	}
	return &transaction{
		executor: &executor{
			db: tx,
			ia: b.ia,
		},
		tx: tx,
	}, nil
}

// Close closes the database.
func (b *Backend) Close() error {
	return b.db.Close()
}

var _ (beacon.Transaction) = (*transaction)(nil)

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

var _ (beacon.DBReadWrite) = (*executor)(nil)

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

func (e *executor) AllRevocations(ctx context.Context) (<-chan beacon.RevocationOrErr, error) {
	e.RLock()
	defer e.RUnlock()
	query := `SELECT RawSignedRev FROM Revocations`
	rows, err := e.db.QueryContext(ctx, query)
	if err != nil {
		return nil, db.NewReadError("Error selecting revocations", err)
	}
	res := make(chan beacon.RevocationOrErr)
	go func() {
		defer log.HandlePanic()
		defer close(res)
		defer rows.Close()
		for rows.Next() {
			var rawRev []byte
			err = rows.Scan(&rawRev)
			if err != nil {
				res <- beacon.RevocationOrErr{Err: db.NewReadError(beacon.ErrReadingRows, err)}
				return
			}
			srev, err := path_mgmt.NewSignedRevInfoFromRaw(rawRev)
			if err != nil {
				err = db.NewDataError(beacon.ErrParse, err)
			}
			res <- beacon.RevocationOrErr{
				Rev: srev,
				Err: err,
			}
			// Continue here as this should not really happen if the insertion
			// is properly guarded.
			// Like this the client might still be able to proceed.
		}
	}()
	return res, nil
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
		var ia addr.IA
		if err := rows.Scan(&ia.I, &ia.A); err != nil {
			return nil, err
		}
		ias = append(ias, ia)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ias, nil
}

func (e *executor) CandidateBeacons(ctx context.Context, setSize int, usage beacon.Usage,
	src addr.IA) (<-chan beacon.BeaconOrErr, error) {

	e.RLock()
	defer e.RUnlock()
	srcCond := ``
	if !src.IsZero() {
		srcCond = `AND StartIsd == ?4 AND StartAs == ?5`
	}
	query := fmt.Sprintf(`
		SELECT b.Beacon, b.InIntfID
		FROM Beacons b
		WHERE ( b.Usage & ?1 ) == ?1 %s AND NOT EXISTS(
			SELECT 1
			FROM IntfToBeacon ib
			JOIN Revocations r USING (IsdID, AsID, IntfID)
			WHERE ib.BeaconRowID = RowID AND r.ExpirationTime >= ?3
		)
		ORDER BY b.HopsLength ASC
		LIMIT ?2
	`, srcCond)
	rows, err := e.db.QueryContext(ctx, query, usage, setSize, util.TimeToSecs(time.Now()),
		src.I, src.A)
	if err != nil {
		return nil, db.NewReadError("Error selecting beacons", err)
	}
	defer rows.Close()
	beacons := make([]beacon.Beacon, 0, setSize)
	var errors []error
	// Read all beacons that are available into memory first to free the lock.
	for rows.Next() {
		var rawBeacon sql.RawBytes
		var inIntfID common.IFIDType
		if err = rows.Scan(&rawBeacon, &inIntfID); err != nil {
			errors = append(errors, db.NewReadError(beacon.ErrReadingRows, err))
			continue
		}
		s, err := beacon.UnpackBeacon(rawBeacon)
		if err != nil {
			errors = append(errors, db.NewDataError(beacon.ErrParse, err))
			continue
		}
		beacons = append(beacons, beacon.Beacon{Segment: s, InIfId: inIntfID})
	}
	if err := rows.Err(); err != nil {
		errors = append(errors, err)
	}
	results := make(chan beacon.BeaconOrErr)
	go func() {
		defer log.HandlePanic()
		defer close(results)
		for _, b := range beacons {
			results <- beacon.BeaconOrErr{Beacon: b}
		}
		for _, e := range errors {
			results <- beacon.BeaconOrErr{Err: e}
			return
		}
	}()
	return results, nil
}

// InsertBeacon inserts the beacon if it is new or updates the changed
// information.
func (e *executor) InsertBeacon(ctx context.Context, b beacon.Beacon,
	usage beacon.Usage) (beacon.InsertStats, error) {

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
			meta.LastUpdated = time.Now()
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
		return insertNewBeacon(ctx, tx, b, usage, e.ia, time.Now())
	})
	if err != nil {
		return ret, err
	}

	ret.Inserted = 1
	return ret, nil

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

// updateExistingBeacon updates the changeable data for an existing beacon
func (e *executor) updateExistingBeacon(ctx context.Context, b beacon.Beacon,
	usage beacon.Usage, rowID int64, now time.Time) error {

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
	_, err = e.db.ExecContext(ctx, inst, fullID, b.InIfId, len(b.Segment.ASEntries), infoTime,
		expTime, lastUpdated, usage, packedSeg, rowID)
	if err != nil {
		return db.NewWriteError("update segment", err)
	}
	return nil
}

func insertNewBeacon(ctx context.Context, tx *sql.Tx, b beacon.Beacon,
	usage beacon.Usage, localIA addr.IA, now time.Time) error {

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
	res, err := tx.ExecContext(ctx, inst, segID, fullID, start.I, start.A, b.InIfId,
		len(b.Segment.ASEntries), infoTime, expTime, lastUpdated, usage, packed)
	if err != nil {
		return db.NewWriteError("insert beacon", err)
	}
	rowID, err := res.LastInsertId()
	if err != nil {
		return db.NewWriteError("retrieve RowID of inserted beacon", err)
	}
	// Insert all interfaces.
	if err = insertInterfaces(ctx, tx, b, rowID, localIA); err != nil {
		return err
	}
	return nil
}

func insertInterfaces(ctx context.Context, tx *sql.Tx, b beacon.Beacon,
	rowID int64, localIA addr.IA) error {

	stmtStr := `INSERT INTO IntfToBeacon (IsdID, AsID, IntfID, BeaconRowID)
				VALUES (?, ?, ?, ?)`
	stmt, err := tx.PrepareContext(ctx, stmtStr)
	if err != nil {
		return db.NewWriteError("prepare insert into IntfToBeacon", err)
	}
	defer stmt.Close()
	for _, as := range b.Segment.ASEntries {
		ia := as.Local
		// Do not insert peering interfaces.
		hof := as.HopEntry.HopField
		if err != nil {
			return db.NewInputDataError("extract hop field", err)
		}
		// Ignore the null interface of the first hop.
		if hof.ConsIngress != 0 {
			_, err = stmt.ExecContext(ctx, ia.I, ia.A, hof.ConsIngress, rowID)
			if err != nil {
				return db.NewWriteError("insert Ingress into IntfToSeg", err,
					"ia", ia, "hof", hof)
			}
		}
		// Ignore the null interface of the last hop
		if hof.ConsEgress != 0 {
			_, err := stmt.ExecContext(ctx, ia.I, ia.A, hof.ConsEgress, rowID)
			if err != nil {
				return db.NewWriteError("insert Egress into IntfToSeg", err,
					"ia", ia, "hof", hof)
			}
		}
	}
	_, err = stmt.ExecContext(ctx, localIA.I, localIA.A, b.InIfId, rowID)
	if err != nil {
		return db.NewWriteError("insert Ingress into IntfToSeg", err,
			"ia", localIA, "inIfId", b.InIfId)
	}
	return nil
}

func (e *executor) DeleteExpiredBeacons(ctx context.Context, now time.Time) (int, error) {
	return e.deleteInTx(ctx, func(tx *sql.Tx) (sql.Result, error) {
		delStmt := `DELETE FROM Beacons WHERE ExpirationTime < ?`
		return tx.ExecContext(ctx, delStmt, now.Unix())
	})
}

func (e *executor) deleteInTx(ctx context.Context,
	delFunc func(tx *sql.Tx) (sql.Result, error)) (int, error) {

	e.Lock()
	defer e.Unlock()
	return db.DeleteInTx(ctx, e.db, delFunc)
}

func (e *executor) DeleteRevokedBeacons(ctx context.Context, now time.Time) (int, error) {
	return e.deleteInTx(ctx, func(tx *sql.Tx) (sql.Result, error) {
		delStmt := `
		DELETE FROM Beacons
		WHERE EXISTS(
			SELECT 1
			FROM IntfToBeacon ib
			JOIN Revocations r USING (IsdID, AsID, IntfID)
			WHERE ib.BeaconRowID = RowID AND r.ExpirationTime >= ?
		)
		`
		return tx.ExecContext(ctx, delStmt, now.Unix())
	})
}

func (e *executor) InsertRevocation(ctx context.Context,
	revocation *path_mgmt.SignedRevInfo) error {

	revInfo, err := revocation.RevInfo()
	if err != nil {
		return db.NewInputDataError("extract revocation", err)
	}
	packedRev, err := revocation.Pack()
	if err != nil {
		return db.NewInputDataError("pack revocation", err)
	}
	e.Lock()
	defer e.Unlock()
	query := `
	INSERT OR REPLACE INTO Revocations
	(IsdID, AsID, IntfID, LinkType, IssuingTime, ExpirationTime, RawSignedRev)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	return db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		existingRev, err := containsNewerRev(ctx, tx, revInfo)
		if err != nil {
			return db.NewReadError("check for existing rev", err)
		}
		if !existingRev {
			_, err = tx.ExecContext(ctx, query, revInfo.IA().I, revInfo.IA().A, revInfo.IfID,
				revInfo.LinkType, revInfo.RawTimestamp, revInfo.Expiration().Unix(), packedRev)
		}
		return err
	})
}

func containsNewerRev(ctx context.Context, tx *sql.Tx,
	revInfo *path_mgmt.RevInfo) (bool, error) {

	var one int
	query := `
	SELECT 1 FROM Revocations
	WHERE IsdID = ? AND AsID = ? AND IntfID = ? AND IssuingTime > ?
	`
	err := tx.QueryRowContext(ctx, query, revInfo.IA().I, revInfo.IA().A,
		revInfo.IfID, revInfo.RawTimestamp).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (e *executor) DeleteRevocation(ctx context.Context, ia addr.IA, ifid common.IFIDType) error {
	query := `
	DELETE FROM Revocations
	WHERE IsdID = ? AND AsID = ? AND IntfID = ?
	`
	_, err := e.deleteInTx(ctx, func(tx *sql.Tx) (sql.Result, error) {
		return tx.ExecContext(ctx, query, ia.I, ia.A, ifid)
	})
	return err
}

func (e *executor) DeleteExpiredRevocations(ctx context.Context, now time.Time) (int, error) {
	query := `
	DELETE FROM Revocations
	WHERE ExpirationTime < ?
	`
	return e.deleteInTx(ctx, func(tx *sql.Tx) (sql.Result, error) {
		return tx.ExecContext(ctx, query, now.Unix())
	})
}
