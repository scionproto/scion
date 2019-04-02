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
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
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
		return nil, common.NewBasicError("Failed to create transaction", err)
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

func (e *executor) CandidateBeacons(ctx context.Context, setSize int,
	usage beacon.Usage) (<-chan beacon.BeaconOrErr, error) {

	e.RLock()
	defer e.RUnlock()
	if e.db == nil {
		return nil, common.NewBasicError("No database open", nil)
	}
	query := `SELECT Beacon, InIntfID FROM Beacons
				WHERE ( Usage & ?1 ) == ?1 ORDER BY HopsLength ASC LIMIT ?2`
	rows, err := e.db.QueryContext(ctx, query, usage, setSize)
	if err != nil {
		return nil, common.NewBasicError("Error selecting beacons", err)
	}
	defer rows.Close()
	beacons := make([]beacon.Beacon, 0, setSize)
	var errors []error
	// Read all beacons that are available into memory first to free the lock.
	for rows.Next() {
		var rawBeacon sql.RawBytes
		var inIntfId common.IFIDType
		if err = rows.Scan(&rawBeacon, &inIntfId); err != nil {
			errors = append(errors, err)
			continue
		}
		s, err := seg.NewSegFromRaw(common.RawBytes(rawBeacon))
		if err != nil {
			errors = append(errors, common.NewBasicError("Unable to parse beacon", err))
		}
		beacons = append(beacons, beacon.Beacon{Segment: s, InIfId: inIntfId})
	}
	if len(beacons) == 0 {
		return nil, common.NewBasicError("No parsebale beacons found", nil, "errs", errors)
	}
	results := make(chan beacon.BeaconOrErr)
	go func() {
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
	usage beacon.Usage) (int, error) {

	// Compute ids outside of the lock.
	segId, err := b.Segment.ID()
	if err != nil {
		return 0, err
	}
	if _, err := b.Segment.FullId(); err != nil {
		return 0, err
	}
	info, err := b.Segment.InfoF()
	if err != nil {
		return 0, err
	}

	e.Lock()
	defer e.Unlock()
	meta, err := e.getBeaconMeta(ctx, segId)
	if err != nil {
		return 0, err
	}
	if meta != nil {
		// TODO(roosd): Implement updates.
		if info.Timestamp().After(meta.InfoTime) {
			return 0, common.NewBasicError("Updating beacons not supported yet", nil)
		}
		return 0, nil
	}
	// Insert new beacon.
	err = db.DoInTx(ctx, e.db, func(ctx context.Context, tx *sql.Tx) error {
		return insertNewBeacon(ctx, tx, b, usage, e.ia, time.Now())
	})
	if err != nil {
		return 0, err
	}
	return 1, nil

}

// getBeaconMeta gets the metadata for existing beacons.
func (e *executor) getBeaconMeta(ctx context.Context, segID common.RawBytes) (*beaconMeta, error) {
	var rowId, infoTime, lastUpdated int64
	query := "SELECT RowID, InfoTime, LastUpdated FROM Beacons WHERE SegID=?"
	err := e.db.QueryRowContext(ctx, query, segID).Scan(&rowId, &infoTime, &lastUpdated)
	// New beacons are not in the table.
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, common.NewBasicError("Failed to lookup beacon", err)
	}
	meta := &beaconMeta{
		RowID:       rowId,
		InfoTime:    time.Unix(infoTime, 0),
		LastUpdated: time.Unix(0, lastUpdated),
	}
	return meta, nil
}

func insertNewBeacon(ctx context.Context, tx *sql.Tx, b beacon.Beacon,
	usage beacon.Usage, localIA addr.IA, now time.Time) error {

	segId, err := b.Segment.ID()
	if err != nil {
		return err
	}
	fullId, err := b.Segment.FullId()
	if err != nil {
		return err
	}
	packed, err := b.Segment.Pack()
	if err != nil {
		return err
	}
	info, err := b.Segment.InfoF()
	if err != nil {
		return err
	}
	start := b.Segment.FirstIA()
	infoTime := info.Timestamp().Unix()
	lastUpdated := now.UnixNano()
	expTime := b.Segment.MaxExpiry().Unix()

	// Insert path segment.
	inst := `INSERT INTO Beacons (SegID, FullID, StartIsd, StartAs, InIntfID, HopsLength, InfoTime, 
			ExpirationTime, LastUpdated, Usage, Beacon)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	res, err := tx.ExecContext(ctx, inst, segId, fullId, start.I, start.A, b.InIfId,
		len(b.Segment.ASEntries), infoTime, expTime, lastUpdated, usage, packed)
	if err != nil {
		return common.NewBasicError("Failed to insert path segment", err)
	}
	rowId, err := res.LastInsertId()
	if err != nil {
		return common.NewBasicError("Failed to retrieve segRowID of inserted segment", err)
	}
	// Insert all interfaces.
	if err = insertInterfaces(ctx, tx, b, rowId, localIA); err != nil {
		return err
	}
	return nil
}

func insertInterfaces(ctx context.Context, tx *sql.Tx, b beacon.Beacon,
	rowId int64, localIA addr.IA) error {

	stmtStr := `INSERT INTO IntfToBeacon (IsdID, AsID, IntfID, BeaconRowID)
				VALUES (?, ?, ?, ?)`
	stmt, err := tx.PrepareContext(ctx, stmtStr)
	if err != nil {
		return common.NewBasicError("Failed to prepare insert into IntfToBeacon", err)
	}
	defer stmt.Close()
	for _, as := range b.Segment.ASEntries {
		ia := as.IA()
		// Do not insert peering interfaces.
		hof, err := as.HopEntries[0].HopField()
		if err != nil {
			return common.NewBasicError("Failed to extract hop field", err)
		}
		// Ignore the null interface of the first hop.
		if hof.ConsIngress != 0 {
			_, err = stmt.ExecContext(ctx, ia.I, ia.A, hof.ConsIngress, rowId)
			if err != nil {
				return common.NewBasicError("Failed to insert Ingress into IntfToSeg", err,
					"ia", ia, "hof", hof)
			}
		}
		// Ignore the null interface of the last hop
		if hof.ConsEgress != 0 {
			_, err := stmt.ExecContext(ctx, ia.I, ia.A, hof.ConsEgress, rowId)
			if err != nil {
				return common.NewBasicError("Failed to insert Egress into IntfToSeg", err,
					"ia", ia, "hof", hof)
			}
		}
	}
	_, err = stmt.ExecContext(ctx, localIA.I, localIA.A, b.InIfId, rowId)
	if err != nil {
		return common.NewBasicError("Failed to insert Ingress into IntfToSeg", err,
			"ia", localIA, "inIfId", b.InIfId)
	}
	return nil
}
