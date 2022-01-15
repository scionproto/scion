package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	pqa_extension "github.com/scionproto/scion/go/lib/ctrl/seg/extensions/pqabeaconing"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/log"
)

const (
	SchemaVersion = 1
	Schema        = `CREATE TABLE Targets (
		RowID INTEGER Not NULL,
		Quality INTEGER NOT NULL,
		Direction INTEGER NOT NULL,
		Uniquifier INTEGER NOT NULL,
		OriginISD INTEGER NOT NULL,
		OriginAS INTEGER NOT NULL,

		UNIQUE (Quality, Direction, Uniquifier, OriginISD, OriginAS)
  PRIMARY KEY (RowID)
	);

	CREATE TABLE BeaconToTarget(
		BeaconRowID INTEGER NOT NULL,
		TargetRowId INTEGER NOT NULL,

      PRIMARY KEY (BeaconRowID)
	);
	`

	TargetsTable       = "Targets"
	BeconToTargetTable = "Beacon2Target"
)

type TargetBackend struct {
	db *sql.DB
	mu sync.Mutex
}

func NewTargetBackend(path string) (*TargetBackend, error) {
	db, err := db.NewSqlite(path, Schema, SchemaVersion)
	if err != nil {
		return nil, err
	}
	return &TargetBackend{
		db: db,
	}, nil
}

type Target struct {
	Quality    pqa_extension.Quality
	Direction  pqa_extension.Direction
	Uniquifier uint32
	ISD        addr.ISD
	AS         addr.AS
}

func (qp *Target) NamedArgs() []interface{} {
	return []interface{}{
		sql.Named("q", qp.Quality),
		sql.Named("d", qp.Direction),
		sql.Named("u", qp.Uniquifier),
		sql.Named("oi", qp.ISD),
		sql.Named("oa", qp.AS),
	}
}

// Executes a query with target names replaced with their respective values
func (tb *TargetBackend) ExecTarget(ctx context.Context, t Target, query string) (sql.Result, error) {
	return tb.db.ExecContext(ctx,
		query,
		sql.Named("q", t.Quality),
		sql.Named("d", t.Direction),
		sql.Named("u", t.Uniquifier),
		sql.Named("oi", t.ISD),
		sql.Named("oa", t.AS))
}

func (tb *TargetBackend) QueryTarget(ctx context.Context, t Target, query string) (*sql.Rows, error) {
	return tb.db.QueryContext(ctx,
		query,
		sql.Named("q", t.Quality),
		sql.Named("d", t.Direction),
		sql.Named("u", t.Uniquifier),
		sql.Named("oi", t.ISD),
		sql.Named("oa", t.AS))
}

func (tb *TargetBackend) AddTarget(ctx context.Context, t Target) error {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	_, err := tb.ExecTarget(ctx, t,
		fmt.Sprintf("INSERT INTO %s (Quality, Direction, Uniquifier, OriginISD, OriginAS) VALUES (@q, @d, @u, @oi, @oa)", TargetsTable))
	return err
}

// Associates a beacon with a target
func (tb *TargetBackend) AddBeaconToTarget(ctx context.Context, beaconID uint64, targetID uint64) error {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	_, err := tb.db.ExecContext(ctx,
		fmt.Sprintf("INSERT INTO %s (BeaconRowID, TargetRowId) VALUES (@b, @t)", BeconToTargetTable),
		sql.Named("b", beaconID),
		sql.Named("t", targetID))
	return err
}

// Returns the Row ID of the target, or -1 if not found
func (tb *TargetBackend) GetTargetRowId(ctx context.Context, t Target) (int, error) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	var id int
	query := fmt.Sprintf("SELECT RowID FROM %s WHERE Quality = @q AND Direction = @d AND Uniquifier = @u AND OriginISD = @oi AND OriginAS = @oa", TargetsTable)
	row, err := tb.QueryTarget(ctx, t, query)
	if err != nil {
		return 0, err
	}
	defer row.Close()
	if row.Next() {
		err = row.Scan(&id)
		if err != nil {
			return 0, err
		} else {
			return id, nil
		}
	}
	return -1, nil
}

// Returns true if a target is already in the DB
func (tb *TargetBackend) TargetExists(ctx context.Context, t Target) (bool, error) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if id, err := tb.GetTargetRowId(ctx, t); err != nil {
		return false, err
	} else if id != -1 {
		return true, nil
	} else {
		return false, nil
	}
}

func (tb *TargetBackend) AddTargetIfNotExists(ctx context.Context, qp Target) error {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	logger := log.FromCtx(ctx)

	// Check if target exists
	if exists, err := tb.TargetExists(ctx, qp); err != nil {
		return err
	} else if exists {
		logger.Debug("Target already exists")
		return nil
	}

	// If not, add target
	if err := tb.AddTarget(ctx, qp); err != nil {
		return err
	}
	logger.Debug("Added target", "target", qp)
	return nil
}

func (tb *TargetBackend) AssociateTargetWithBeacon(ctx context.Context, targetRowId int, beaconRoWId int) {

}

func (tb *TargetBackend) Close() error {
	return tb.db.Close()
}
