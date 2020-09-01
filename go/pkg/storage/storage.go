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
	"fmt"
	"io"

	"github.com/scionproto/scion/go/cs/beacon"
	sqlitebeacondb "github.com/scionproto/scion/go/cs/beacon/beacondbsqlite"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	sqlitepathdb "github.com/scionproto/scion/go/lib/pathdb/sqlite"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/revcache/memrevcache"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
	sqliterenewaldb "github.com/scionproto/scion/go/pkg/trust/renewal/sqlite"
	sqlitetrustdb "github.com/scionproto/scion/go/pkg/trust/sqlite"
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
	SampleRenewalDB = DBConfig{
		Connection: "/share/data/trustdb/%s.renewal.db",
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

func NewBeaconStorage(c DBConfig, ia addr.IA) (beacon.DB, error) {
	log.Info("Connecting BeaconDB", "backend", BackendSqlite, "connection", c.Connection)
	db, err := sqlitebeacondb.New(c.Connection, ia)
	if err != nil {
		return nil, err
	}
	SetConnLimits(db, c)
	return db, nil
}

func NewPathStorage(c DBConfig) (pathdb.PathDB, error) {
	log.Info("Connecting PathDB", "backend", BackendSqlite, "connection", c.Connection)
	db, err := sqlitepathdb.New(c.Connection)
	if err != nil {
		return nil, err
	}
	SetConnLimits(db, c)
	return db, nil
}

func NewRevocationStorage() revcache.RevCache {
	return memrevcache.New()
}

func NewTrustStorage(c DBConfig) (trust.DB, error) {
	log.Info("Connecting TrustDB", "backend", BackendSqlite, "connection", c.Connection)
	db, err := sqlitetrustdb.New(c.Connection)
	if err != nil {
		return nil, err
	}
	SetConnLimits(db, c)
	return db, nil
}

func NewRenewalStorage(c DBConfig) (renewal.DB, error) {
	log.Info("Connecting RenewalDB", "backend", BackendSqlite, "connection", c.Connection)
	db, err := sqliterenewaldb.New(c.Connection)
	if err != nil {
		return nil, err
	}
	SetConnLimits(db, c)
	return db, nil
}
