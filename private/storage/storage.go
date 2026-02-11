// Copyright 2020 Anapaya Systems
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

// Package storage provides factories for various application storage backends.
package storage

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/config"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/periodic"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/revcache/memrevcache"
	beaconstorage "github.com/scionproto/scion/private/storage/beacon"
	sqlitebeacondb "github.com/scionproto/scion/private/storage/beacon/sqlite"
	"github.com/scionproto/scion/private/storage/cleaner"
	"github.com/scionproto/scion/private/storage/db"
	sqlitelevel1 "github.com/scionproto/scion/private/storage/drkey/level1/sqlite"
	sqlitelevel2 "github.com/scionproto/scion/private/storage/drkey/level2/sqlite"
	sqlitesecret "github.com/scionproto/scion/private/storage/drkey/secret/sqlite"
	sqlitepathdb "github.com/scionproto/scion/private/storage/path/sqlite"
	truststorage "github.com/scionproto/scion/private/storage/trust"
	sqlitetrustdb "github.com/scionproto/scion/private/storage/trust/sqlite"
	"github.com/scionproto/scion/private/trust"
)

// Backend indicates the database backend type.
type Backend string

const (
	// BackendSqlite indicates an sqlite backend.
	BackendSqlite Backend = "sqlite"
	// DefaultPath indicates the default connection string for a generic database.
	DefaultPath              = "/share/scion.db"
	DefaultTrustDBPath       = "/share/data/%s.trust.db"
	DefaultPathDBPath        = "/share/cache/%s.path.db"
	DefaultDRKeyLevel1DBPath = "/share/cache/%s.drkey_level1.db"
	DefaultDRKeyLevel2DBPath = "/share/cache/%s.drkey_level2.db"
	DefaultDRKeySVDBPath     = "/share/cache/%s.drkey_secret_value.db"
)

// Default samples for various databases.
var (
	SampleBeaconDB = DBConfig{
		Connection: "/share/cache/%s.beacon.db",
	}
	SamplePathDB = DBConfig{
		Connection: DefaultPathDBPath,
	}
	SampleTrustDB = DBConfig{
		Connection: DefaultTrustDBPath,
	}
	SampleDRKeyLevel1DB = DBConfig{
		Connection: DefaultDRKeyLevel1DBPath,
	}
	SampleDRKeyLevel2DB = DBConfig{
		Connection: DefaultDRKeyLevel2DBPath,
	}
	SampleDRKeySecretValueDB = DBConfig{
		Connection: DefaultDRKeySVDBPath,
	}
)

// SetID returns a clone of the configuration that has the ID set on the connection string.
func SetID(cfg DBConfig, id string) *DBConfig {
	cfg.Connection = fmt.Sprintf(cfg.Connection, id)
	return &cfg
}

// TrustDB extends the trust.DB interface with methods used outside of the trust
// package.
type TrustDB interface {
	io.Closer
	trust.DB
	truststorage.TrustAPI
}

type BeaconDB interface {
	io.Closer
	beacon.DB
	beaconstorage.BeaconAPI
}

type PathDB interface {
	io.Closer
	pathdb.DB
}

var _ (config.Config) = (*DBConfig)(nil)

// DBConfig is the configuration for the connection to a database.
type DBConfig struct {
	config.NoDefaulter
	Connection       string `toml:"connection,omitempty"`
	MaxOpenReadConns int    `toml:"max_open_read_conns,omitempty"`
	MaxIdleReadConns int    `toml:"max_idle_read_conns,omitempty"`
	allowEmptyConn   bool
}

type writeDefault struct {
	*DBConfig
	defaultPath string
}

func (w writeDefault) InitDefaults() {
	if w.Connection == "" {
		w.Connection = w.defaultPath
	}
}

func (cfg *DBConfig) WithDefault(path string) config.Defaulter {
	return writeDefault{DBConfig: cfg, defaultPath: path}
}

func (cfg *DBConfig) WithAllowEmptyConn() *DBConfig {
	c := *cfg
	c.allowEmptyConn = true
	return &c
}

func (cfg *DBConfig) Validate() error {
	if cfg.Connection == "" && !cfg.allowEmptyConn {
		return serrors.New("connection must be set")
	}
	return nil
}

// Sample writes a config sample to the writer.
func (cfg *DBConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, sample)
}

// ConfigName is the key in the toml file.
func (cfg *DBConfig) ConfigName() string {
	return "db"
}

func NewBeaconStorage(c DBConfig, ia addr.IA, metrics cleaner.Metrics) (BeaconDB, error) {
	log.Info("Connecting BeaconDB", "backend", BackendSqlite, "connection", c.Connection)
	db, err := sqlitebeacondb.New(
		c.Connection,
		ia,
		&db.SqliteConfig{
			MaxOpenReadConns: c.MaxOpenReadConns,
			MaxIdleReadConns: c.MaxIdleReadConns,
		},
	)
	if err != nil {
		return nil, err
	}

	// Start a periodic task that cleans up the expired beacons.
	//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
	cleaner := periodic.Start(
		cleaner.New(
			func(ctx context.Context) (int, error) {
				checkpoint(ctx, db.DB())
				return db.DeleteExpiredBeacons(ctx, time.Now())
			},
			"control_beaconstorage_cleaner",
			metrics,
		),
		30*time.Second,
		30*time.Second,
	)
	return beaconDBWithCleaner{
		BeaconDB: db,
		cleaner:  cleaner,
	}, nil
}

// beaconDBWithCleaner implements the BeaconDB interface and stops both the
// database and the cleanup task on Close.
type beaconDBWithCleaner struct {
	BeaconDB
	cleaner *periodic.Runner
}

func (b beaconDBWithCleaner) Close() error {
	b.cleaner.Kill()
	return b.BeaconDB.Close()
}

func NewPathStorage(c DBConfig, metrics cleaner.Metrics) (PathDB, error) {
	log.Info("Connecting PathDB", "backend", BackendSqlite, "connection", c.Connection)
	db, err := sqlitepathdb.New(c.Connection,
		&db.SqliteConfig{
			MaxOpenReadConns: c.MaxOpenReadConns,
			MaxIdleReadConns: c.MaxIdleReadConns,
		},
	)
	if err != nil {
		return nil, err
	}

	// Start a periodic task that cleans up the expired path segments.
	//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
	cleaner := periodic.Start(
		cleaner.New(
			func(ctx context.Context) (int, error) {
				checkpoint(ctx, db.DB())
				return db.DeleteExpired(ctx, time.Now())
			},
			"control_pathstorage_cleaner",
			metrics,
		),
		30*time.Second,
		30*time.Second,
	)
	return pathDBWithCleaner{
		DB:       db,
		cleaner:  cleaner,
		dbCloser: db,
	}, nil
}

func NewInMemoryPathStorage(metrics cleaner.Metrics) (PathDB, error) {
	log.Info("Creating in-memory PathDB", "backend", BackendSqlite)
	// Use timestamp to create unique database name for each instance
	dbName := fmt.Sprintf("in_memory_path_db_%d", time.Now().UnixNano())
	db, err := sqlitepathdb.New(dbName, &db.SqliteConfig{
		InMemory:         true,
		MaxOpenReadConns: 1,
		MaxIdleReadConns: 1,
	})

	if err != nil {
		return nil, err
	}

	// Start a periodic task that cleans up the expired path segments.
	//nolint:staticcheck // SA1019: fix later (https://github.com/scionproto/scion/issues/4776).
	cleaner := periodic.Start(
		cleaner.New(
			func(ctx context.Context) (int, error) {
				checkpoint(ctx, db.DB())
				return db.DeleteExpired(ctx, time.Now())
			},
			"control_pathstorage_cleaner",
			metrics,
		),
		30*time.Second,
		30*time.Second,
	)
	return pathDBWithCleaner{
		DB:       db,
		cleaner:  cleaner,
		dbCloser: db,
	}, nil
}

// pathDBWithCleaner implements the path DB interface and stops both the
// database and the cleanup task on Close.
type pathDBWithCleaner struct {
	pathdb.DB
	cleaner  *periodic.Runner
	dbCloser io.Closer
}

func (b pathDBWithCleaner) Close() error {
	b.cleaner.Kill()
	return b.dbCloser.Close()
}

func NewRevocationStorage() revcache.RevCache {
	return memrevcache.New()
}

func NewTrustStorage(c DBConfig) (TrustDB, error) {
	log.Info("Connecting TrustDB", "backend", BackendSqlite, "connection", c.Connection)
	db, err := sqlitetrustdb.New(
		c.Connection,
		&db.SqliteConfig{
			MaxOpenReadConns: c.MaxOpenReadConns,
			MaxIdleReadConns: c.MaxIdleReadConns,
		},
	)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func NewInMemoryTrustStorage() (TrustDB, error) {
	log.Info("Creating in-memory TrustDB", "backend", BackendSqlite)
	dbName := fmt.Sprintf("in_memory_trust_db_%d", time.Now().UnixNano())
	return sqlitetrustdb.New(
		dbName,
		&db.SqliteConfig{
			MaxOpenReadConns: 1,
			MaxIdleReadConns: 1,
			InMemory:         true,
		},
	)
}

func NewDRKeySecretValueStorage(c DBConfig) (drkey.SecretValueDB, error) {
	log.Info("Connecting DRKeySecretValueDB", "	", BackendSqlite, "connection", c.Connection)
	db, err := sqlitesecret.NewBackend(
		c.Connection,
		&db.SqliteConfig{
			MaxOpenReadConns: c.MaxOpenReadConns,
			MaxIdleReadConns: c.MaxIdleReadConns,
		},
	)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func NewDRKeyLevel1Storage(c DBConfig) (drkey.Level1DB, error) {
	log.Info("Connecting DRKeyLevel1DB", "	", BackendSqlite, "connection", c.Connection)
	db, err := sqlitelevel1.NewBackend(
		c.Connection,
		&db.SqliteConfig{
			MaxOpenReadConns: c.MaxOpenReadConns,
			MaxIdleReadConns: c.MaxIdleReadConns,
		},
	)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func NewDRKeyLevel2Storage(c DBConfig) (drkey.Level2DB, error) {
	log.Info("Connecting DRKeyDB", "	", BackendSqlite, "connection", c.Connection)
	db, err := sqlitelevel2.NewBackend(
		c.Connection,
		&db.SqliteConfig{
			MaxOpenReadConns: c.MaxOpenReadConns,
			MaxIdleReadConns: c.MaxIdleReadConns,
		},
	)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func checkpoint(ctx context.Context, db *db.Sqlite) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stats, err := db.Checkpoint(ctx)
	if err != nil {
		log.FromCtx(ctx).Error("Failed to checkpoint", "err", err)
		return
	}
	if stats.Busy > 0 {
		log.FromCtx(ctx).Info("Checkpointed with busy readers",
			"stats.busy", stats.Busy,
			"stats.log_frames", stats.LogFrames,
			"stats.checkpointed", stats.Checkpointed,
		)
		return
	}
	log.FromCtx(ctx).Debug("Checkpointed",
		"stats.busy", stats.Busy,
		"stats.log_frames", stats.LogFrames,
		"stats.checkpointed", stats.Checkpointed,
	)

	// Panic if the number of frames in the WAL is above 1,000,000 frames (~4 GB for 4 KB pages).
	// Checkpoint should happen at 1,000 frames (4 MB for 4 KB pages).
	if stats.LogFrames > 1_000_000 && stats.Checkpointed != stats.LogFrames {
		panic(
			fmt.Sprintf(
				"An unreasonable amount of frames is present in the WAL: %d",
				stats.LogFrames,
			),
		)
	}
}
