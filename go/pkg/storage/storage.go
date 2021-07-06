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

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/infra/modules/cleaner"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/revcache/memrevcache"
	sqlitebeacondb "github.com/scionproto/scion/go/pkg/storage/beacon/sqlite"
	sqlitepathdb "github.com/scionproto/scion/go/pkg/storage/path/sqlite"
	truststorage "github.com/scionproto/scion/go/pkg/storage/trust"
	sqlitetrustdb "github.com/scionproto/scion/go/pkg/storage/trust/sqlite"
	"github.com/scionproto/scion/go/pkg/trust"
)

// Backend indicates the database backend type.
type Backend string

const (
	// BackendSqlite indicates an sqlite backend.
	BackendSqlite Backend = "sqlite"
	// DefaultPath indicates the default connection string for a generic database.
	DefaultPath        = "/share/scion.db"
	DefaultTrustDBPath = "/share/data/%s.trust.db"
	DefaultPathDBPath  = "/share/cache/%s.path.db"
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
}

type PathDB interface {
	io.Closer
	pathdb.DB
}

var _ (config.Config) = (*DBConfig)(nil)

// DBConfig is the configuration for the connection to a database.
type DBConfig struct {
	Connection   string `toml:"connection,omitempty"`
	MaxOpenConns int    `toml:"max_open_conns,omitempty"`
	MaxIdleConns int    `toml:"max_idle_conns,omitempty"`
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

// SetConnLimits sets the maximum number of open and idle connections based on the configuration.
// Limits of 0 mean the Go default will be used.
func SetConnLimits(d db.LimitSetter, c DBConfig) {
	if c.MaxOpenConns != 0 {
		d.SetMaxOpenConns(c.MaxOpenConns)
	}
	if c.MaxIdleConns != 0 {
		d.SetMaxIdleConns(c.MaxIdleConns)
	}
}

func (cfg *DBConfig) InitDefaults() {
	if cfg.Connection == "" {
		cfg.Connection = DefaultPath
	}
}

func (cfg *DBConfig) Validate() error {
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

func NewBeaconStorage(c DBConfig, ia addr.IA) (BeaconDB, error) {
	log.Info("Connecting BeaconDB", "backend", BackendSqlite, "connection", c.Connection)
	db, err := sqlitebeacondb.New(c.Connection, ia)
	if err != nil {
		return nil, err
	}
	SetConnLimits(db, c)

	// Start a periodic task that cleans up the expired beacons.
	cleaner := periodic.Start(
		cleaner.New(
			func(ctx context.Context) (int, error) {
				return db.DeleteExpiredBeacons(ctx, time.Now())
			},
			"control_beaconstorage_cleaner",
		),
		30*time.Second,
		30*time.Second,
	)
	return beaconDBWithCleaner{
		DB:       db,
		cleaner:  cleaner,
		dbCloser: db,
	}, nil
}

// beaconDBWithCleaner implements the BeaconDB interface and stops both the
// database and the cleanup task on Close.
type beaconDBWithCleaner struct {
	beacon.DB
	cleaner  *periodic.Runner
	dbCloser io.Closer
}

func (b beaconDBWithCleaner) Close() error {
	b.cleaner.Kill()
	return b.dbCloser.Close()
}

func NewPathStorage(c DBConfig) (PathDB, error) {
	log.Info("Connecting PathDB", "backend", BackendSqlite, "connection", c.Connection)
	db, err := sqlitepathdb.New(c.Connection)
	if err != nil {
		return nil, err
	}
	SetConnLimits(db, c)

	// Start a periodic task that cleans up the expired path segments.
	cleaner := periodic.Start(
		cleaner.New(
			func(ctx context.Context) (int, error) {
				return db.DeleteExpired(ctx, time.Now())
			},
			"control_pathstorage_cleaner",
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
	db, err := sqlitetrustdb.New(c.Connection)
	if err != nil {
		return nil, err
	}
	SetConnLimits(db, c)
	return db, nil
}
