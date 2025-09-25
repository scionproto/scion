// Copyright 2025 ETH Zurich, Anapaya Systems
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

package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"strings"
	"sync"

	_ "modernc.org/sqlite" // sqlite driver
)

type Reader interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	Stats() sql.DBStats
}

// SqliteConfig allows configuring the sqlite database instance.
type SqliteConfig struct {
	MaxOpenReadConns int
	MaxIdleReadConns int
	InMemory         bool
}

// NewSqlite creates a new sqlite database with a read and write connection pool. The write
// connection pool is limited to one open connection to avoid contention. The read connection pool
// is configured with a sane default limit depending on the number of CPUs (can be overridden via
// config).
//
// The [dbutil.Sqlite.Full] connection can be used to perform any operation, including reads and
// opening transactions. The [dbutil.Sqlite.ReadOnly] connection should only be used for read
// operations. Read-only transactions are currently not supported.
func NewSqlite(path string, cfg *SqliteConfig) (*Sqlite, error) {
	c := func() SqliteConfig {
		if cfg != nil {
			return *cfg
		}
		return SqliteConfig{}
	}()

	// :memory: is ambiguous. With the combination of shared cache and in-memory, multiple
	// connections can access the same database, violating the expectation that there is a read pool
	// with max open connections of 1.
	if strings.Contains(path, ":memory:") {
		return nil, fmt.Errorf("use explicitly named memory database")
	}
	noFile, ok := strings.CutPrefix(path, "file:")

	connParams := make(url.Values)
	// By default, SQLite starts transactions in DEFERRED mode: they are considered read only. They
	// are upgraded to a write transaction that requires a database lock in-flight, when query
	// containing a write/update/delete statement is issued.
	//
	// The problem is that by upgrading a transaction after it has started, SQLite will immediately
	// return a SQLITE_BUSY error without respecting the busy_timeout previously mentioned, if the
	// database is already locked by another connection.
	//
	// This is why you should start your transactions with BEGIN IMMEDIATE instead of only BEGIN. If
	// the database is locked when the transaction starts, SQLite will respect busy_timeout.
	connParams.Add("_txlock", "immediate")
	// The WAL journal mode provides a [Write-Ahead Log](https://www.sqlite.org/wal.html) provides
	// more concurrency as readers do not block writers and a writer does not block readers,
	// contrary to the default mode where readers block writers and vice versa.
	connParams.Add("_pragma", "journal_mode(WAL)")
	// Setting a bigger busy_timeout helps to prevent SQLITE_BUSY errors. The timeout is in
	// milliseconds.
	connParams.Add("_pragma", "busy_timeout(1000)")
	// When synchronous is NORMAL, the SQLite database engine will still sync at the most critical
	// moments, but less often than in FULL mode. WAL mode is safe from corruption with
	// synchronous=NORMAL.
	connParams.Add("_pragma", "synchronous(NORMAL)")
	// Enforce foreign key constraints.
	connParams.Add("_pragma", "foreign_keys(1)")
	// Use shared cache for in-memory databases to allow multiple connections.
	if c.InMemory {
		registerMemoryDB(noFile)
		connParams.Add("mode", "memory")
		// Use shared cache such that the read and write connections share the same
		// in-memory database.
		connParams.Add("cache", "shared")
	}

	// Construct the connection URL.
	connUrl := path + "?" + connParams.Encode()
	if !ok {
		connUrl = "file:" + connUrl
	}

	write, err := sql.Open("sqlite", connUrl)
	if err != nil {
		return nil, fmt.Errorf("opening write database: %w", err)
	}
	write.SetMaxOpenConns(1)

	read, err := sql.Open("sqlite", connUrl)
	if err != nil {
		defer write.Close()
		return nil, fmt.Errorf("opening read database: %w", err)
	}

	// Set max open and idle connections for read DB.
	{
		if c.MaxOpenReadConns == 0 {
			c.MaxOpenReadConns = max(4, runtime.NumCPU())
		}
		read.SetMaxOpenConns(c.MaxOpenReadConns)

		if c.MaxIdleReadConns != 0 {
			read.SetMaxIdleConns(c.MaxIdleReadConns)
		}
	}

	db := &Sqlite{
		Full:     write,
		ReadOnly: read,
	}
	if c.InMemory {
		runtime.AddCleanup(db, func(name string) { unregisterMemoryDB(name) }, noFile)
	}
	return db, nil
}

type Sqlite struct {
	Full     *sql.DB
	ReadOnly Reader
}

func (db *Sqlite) Setup(schema string, schemaVersion int) error {
	// Check the schema version and set up new DB if necessary.
	var existingVersion int
	if err := db.Full.QueryRow("PRAGMA user_version;").Scan(&existingVersion); err != nil {
		return fmt.Errorf("checking database schema version: %w", err)
	}
	switch {
	case existingVersion == 0:
		_, err := db.Full.Exec(schema)
		if err != nil {
			return fmt.Errorf("appliying schema: %w", err)
		}
		// Write schema version to database.
		_, err = db.Full.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion))
		if err != nil {
			return fmt.Errorf("writing schema version: %w", err)
		}
		return nil
	case existingVersion != schemaVersion:
		return fmt.Errorf("database schema version mismatch: expected %d, have %d",
			schemaVersion, existingVersion,
		)
	default:
		return nil
	}
}

// Checkpoint runs a WAL checkpoint with FULL mode on the write database.
func (db *Sqlite) Checkpoint(ctx context.Context) (CheckpointStats, error) {
	return Checkpoint(ctx, db.Full, "FULL")
}

type CheckpointStats struct {
	Busy         int
	LogFrames    int
	Checkpointed int
}

// Checkpoint runs a WAL checkpoint with the given mode (PASSIVE, FULL, RESTART, TRUNCATE). It
// returns the three integers that SQLite reports:
//
//	busy        = number of frames not checkpointed due to active readers
//	log         = total frames in the WAL
//	checkpointed= frames actually checkpointed
func Checkpoint(ctx context.Context, db *sql.DB, mode string) (CheckpointStats, error) {
	var busy, logFrames, checkpointed int
	query := fmt.Sprintf("PRAGMA wal_checkpoint(%s);", mode)
	if err := db.QueryRowContext(ctx, query).Scan(&busy, &logFrames, &checkpointed); err != nil {
		return CheckpointStats{}, fmt.Errorf("performing checkpoint: %w", err)
	}
	return CheckpointStats{
		Busy:         busy,
		LogFrames:    logFrames,
		Checkpointed: checkpointed,
	}, nil
}

func (db *Sqlite) Close() error {
	var errs []error

	if err := db.Full.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing write db: %w", err))
	}
	if err := db.ReadOnly.(*sql.DB).Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing read db: %w", err))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return nil
}

// memoryDBCheck is a safety mechanism to prevent multiple in-memory databases with the same
// name. Such databases would share the same underlying database, leading to unexpected behavior in
// tests.
var memoryDBCheck = struct {
	mtx sync.Mutex
	dbs map[string]struct{}
}{
	dbs: make(map[string]struct{}),
}

func registerMemoryDB(name string) {
	memoryDBCheck.mtx.Lock()
	defer memoryDBCheck.mtx.Unlock()
	if _, ok := memoryDBCheck.dbs[name]; ok {
		panic(fmt.Sprintf("memory database with name %s already exists", name))
	}
	memoryDBCheck.dbs[name] = struct{}{}
}

func unregisterMemoryDB(name string) {
	memoryDBCheck.mtx.Lock()
	defer memoryDBCheck.mtx.Unlock()
	delete(memoryDBCheck.dbs, name)
}
