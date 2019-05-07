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
	"strconv"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/beacon_srv/internal/beacon/beacondbsqlite"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/log"
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
	// MaxOpenConnsKey is the key for max open conns in the config mapping.
	MaxOpenConnsKey = "maxopenconns"
	// MaxIdleConnsKey is the key for max idle conns in the config mapping.
	MaxIdleConnsKey = "maxidleconns"
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
	val, ok, _ := cfg.parsedInt(MaxOpenConnsKey)
	return val, ok
}

// MaxIdleConns returns the limit for maximum idle connections to the database.
func (cfg *BeaconDBConf) MaxIdleConns() (int, bool) {
	val, ok, _ := cfg.parsedInt(MaxIdleConnsKey)
	return val, ok
}

func (cfg *BeaconDBConf) parsedInt(key string) (int, bool, error) {
	val := (*cfg)[key]
	if val == "" {
		return 0, false, nil
	}
	i, err := strconv.Atoi(val)
	return i, true, err
}

// Validate validates that all values are parsable, and the backend is set.
func (cfg *BeaconDBConf) Validate() error {
	if err := cfg.validateLimits(); err != nil {
		return err
	}
	switch cfg.Backend() {
	case BackendSqlite:
		return nil
	case backendNone:
		return common.NewBasicError("No backend set", nil)
	}
	return common.NewBasicError("Unsupported backend", nil, "backend", cfg.Backend())
}

func (cfg *BeaconDBConf) validateLimits() error {
	if _, _, err := cfg.parsedInt(MaxOpenConnsKey); err != nil {
		return common.NewBasicError("Invalid MaxOpenConns", nil, "value", (*cfg)[MaxOpenConnsKey])
	}
	if _, _, err := cfg.parsedInt(MaxIdleConnsKey); err != nil {
		return common.NewBasicError("Invalid MaxIdleConns", nil, "value", (*cfg)[MaxIdleConnsKey])
	}
	return nil
}

// Sample writes a config sample to the writer.
func (cfg *BeaconDBConf) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, fmt.Sprintf(beaconDbSample, ctx[config.ID]))
}

// ConfigName is the key in the toml file.
func (cfg *BeaconDBConf) ConfigName() string {
	return "beaconDB"
}

// New creates a BeaconDB from the config.
func (cfg *BeaconDBConf) New(ia addr.IA) (beacon.DB, error) {
	log.Info("Connecting BeaconDB", "backend", cfg.Backend(), "connection", cfg.Connection())
	var err error
	var db beacon.DB

	switch cfg.Backend() {
	case BackendSqlite:
		db, err = beacondbsqlite.New(cfg.Connection(), ia)
	default:
		return nil, common.NewBasicError("Unsupported backend", nil, "backend", cfg.Backend())
	}
	if err != nil {
		return nil, err
	}
	setConnLimits(cfg, db)
	return db, nil
}

func setConnLimits(cfg *BeaconDBConf, db beacon.DB) {
	if m, ok := cfg.MaxOpenConns(); ok {
		db.SetMaxOpenConns(m)
	}
	if m, ok := cfg.MaxIdleConns(); ok {
		db.SetMaxIdleConns(m)
	}
}
