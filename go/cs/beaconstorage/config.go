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

// Package beaconstorage provides a "factory" for beacon stores.
// A config containing the backend type and the connection string
// are used to create a specific beacon db.
package beaconstorage

import (
	"fmt"
	"io"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beacon/beacondbsqlite"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

// Backend indicates the database backend type.
type Backend string

const (
	// backendNone is the empty backend. It defaults to sqlite.
	backendNone Backend = ""
	// BackendSqlite indicates an sqlite backend.
	BackendSqlite Backend = "sqlite"
)

const (
	// BackendKey is the backend key in the config mapping.
	BackendKey = "backend"
	// ConnectionKey is the connection key in the config mapping.
	ConnectionKey = "connection"
)

var _ (config.Config) = (*BeaconDBConf)(nil)

// BeaconDBConf is the configuration for the connection to the trust database.
type BeaconDBConf map[string]string

// InitDefaults chooses the sqlite backend if no backend is set and sets all keys
// to lower case.
func (cfg *BeaconDBConf) InitDefaults() {
	if *cfg == nil {
		*cfg = make(BeaconDBConf)
	}
	m := *cfg
	util.LowerKeys(m)
	if cfg.Backend() == backendNone {
		m[BackendKey] = string(BackendSqlite)
	}
}

// Backend returns the database backend type.
func (cfg *BeaconDBConf) Backend() Backend {
	return Backend((*cfg)[BackendKey])
}

// Connection returns the database connection information.
func (cfg *BeaconDBConf) Connection() string {
	return (*cfg)[ConnectionKey]
}

// MaxOpenConns returns the limit for maximum open connections to the database.
func (cfg *BeaconDBConf) MaxOpenConns() (int, bool) {
	return db.ConfiguredMaxOpenConns(*cfg)
}

// MaxIdleConns returns the limit for maximum idle connections to the database.
func (cfg *BeaconDBConf) MaxIdleConns() (int, bool) {
	return db.ConfiguredMaxIdleConns(*cfg)
}

// Validate validates that all values are parsable, and the backend is set.
func (cfg *BeaconDBConf) Validate() error {
	if err := db.ValidateConfigLimits(*cfg); err != nil {
		return err
	}
	if err := cfg.validateBackend(); err != nil {
		return err
	}
	return nil
}

func (cfg *BeaconDBConf) validateBackend() error {
	switch cfg.Backend() {
	case BackendSqlite:
		return nil
	case backendNone:
		return serrors.New("No backend set")
	}
	return common.NewBasicError("Unsupported backend", nil, "backend", cfg.Backend())
}

func (cfg *BeaconDBConf) validateConnection() error {
	if cfg.Connection() == "" {
		return serrors.New("empty connection not allowed")
	}
	return nil
}

// Sample writes a config sample to the writer.
func (cfg *BeaconDBConf) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, fmt.Sprintf(beaconDbSample, ctx[config.ID]))
}

// ConfigName is the key in the toml file.
func (cfg *BeaconDBConf) ConfigName() string {
	return "beacon_db"
}

// New creates a BeaconDB from the config.
func (cfg *BeaconDBConf) New(ia addr.IA) (beacon.DB, error) {
	log.Info("Connecting BeaconDB", "backend", cfg.Backend(), "connection", cfg.Connection())
	var err error
	var bdb beacon.DB

	switch cfg.Backend() {
	case BackendSqlite:
		bdb, err = beacondbsqlite.New(cfg.Connection(), ia)
	default:
		return nil, common.NewBasicError("Unsupported backend", nil, "backend", cfg.Backend())
	}
	if err != nil {
		return nil, err
	}
	bdb = beacon.DBWithMetrics("std", bdb)
	db.SetConnLimits(cfg, bdb)
	return bdb, nil
}

// NewStore creates a new beacon store backed by the configured database.
func (cfg *BeaconDBConf) NewStore(ia addr.IA, policies beacon.Policies) (Store, error) {
	db, err := cfg.New(ia)
	if err != nil {
		return nil, err
	}
	return beacon.NewBeaconStore(policies, db)
}

// NewCoreStore creates a new core beacon store backed by the configured database.
func (cfg *BeaconDBConf) NewCoreStore(ia addr.IA, policies beacon.CorePolicies) (Store, error) {
	db, err := cfg.New(ia)
	if err != nil {
		return nil, err
	}
	return beacon.NewCoreBeaconStore(policies, db)
}
