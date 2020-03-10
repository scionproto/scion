// Copyright 2018 Anapaya Systems
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

package pathstorage

import (
	"fmt"
	"io"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	sqlitepathdb "github.com/scionproto/scion/go/lib/pathdb/sqlite"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/revcache/memrevcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

type Backend string

const (
	BackendNone   Backend = ""
	BackendSqlite Backend = "sqlite"
	BackendMem    Backend = "mem"
)

const (
	BackendKey    = "backend"
	ConnectionKey = "connection"
)

var _ config.Config = (*PathDBConf)(nil)

// PathDBConf is the configuration for the connection to the path database.
type PathDBConf map[string]string

// InitDefaults choses the sqlite backend if no backend is set.
func (cfg *PathDBConf) InitDefaults() {
	if *cfg == nil {
		*cfg = make(PathDBConf)
	}
	m := *cfg
	util.LowerKeys(m)
	if cfg.Backend() == BackendNone {
		m[BackendKey] = string(BackendSqlite)
	}
}

func (cfg *PathDBConf) Backend() Backend {
	return Backend((*cfg)[BackendKey])
}

func (cfg *PathDBConf) Connection() string {
	return (*cfg)[ConnectionKey]
}

func (cfg *PathDBConf) MaxOpenConns() (int, bool) {
	return db.ConfiguredMaxOpenConns(*cfg)
}

func (cfg *PathDBConf) MaxIdleConns() (int, bool) {
	return db.ConfiguredMaxIdleConns(*cfg)
}

func (cfg *PathDBConf) Sample(dst io.Writer, _ config.Path, ctx config.CtxMap) {
	config.WriteString(dst, fmt.Sprintf(pathDbSample, ctx[config.ID]))
}

func (cfg *PathDBConf) ConfigName() string {
	return "path_db"
}

// Validate validates the configuration, should be called after InitDefaults.
func (cfg *PathDBConf) Validate() error {
	if err := db.ValidateConfigLimits(*cfg); err != nil {
		return err
	}
	if err := cfg.validateBackend(); err != nil {
		return err
	}
	if err := cfg.validateConnection(); err != nil {
		return err
	}
	return nil
}

func (cfg *PathDBConf) validateBackend() error {
	switch cfg.Backend() {
	case BackendSqlite:
		return nil
	case BackendNone:
		return serrors.New("No backend set")
	}
	return common.NewBasicError("Unsupported backend", nil, "backend", cfg.Backend())
}

func (cfg *PathDBConf) validateConnection() error {
	if cfg.Connection() == "" {
		return serrors.New("Empty connection not allowed")
	}
	return nil
}

var _ config.Config = (*RevCacheConf)(nil)

// RevCacheConf is the configuration for the connection to the revocation cache.
type RevCacheConf map[string]string

// InitDefaults chooses the in-memory backend if no backend is set.
func (cfg *RevCacheConf) InitDefaults() {
	if *cfg == nil {
		*cfg = make(RevCacheConf)
	}
	m := *cfg
	util.LowerKeys(m)
	if cfg.Backend() == BackendNone {
		m[BackendKey] = string(BackendMem)
	}
}

func (cfg *RevCacheConf) Backend() Backend {
	return Backend((*cfg)[BackendKey])
}

func (cfg *RevCacheConf) Connection() string {
	return (*cfg)[ConnectionKey]
}

func (cfg *RevCacheConf) MaxOpenConns() (int, bool) {
	return db.ConfiguredMaxOpenConns(*cfg)
}

func (cfg *RevCacheConf) MaxIdleConns() (int, bool) {
	return db.ConfiguredMaxIdleConns(*cfg)
}

// Validate validates the configuration, should be called after InitDefaults.
func (cfg *RevCacheConf) Validate() error {
	if err := db.ValidateConfigLimits(*cfg); err != nil {
		return err
	}
	if err := cfg.validateBackend(); err != nil {
		return err
	}
	if err := cfg.validateConnection(); err != nil {
		return err
	}
	return nil
}

func (cfg *RevCacheConf) Sample(dst io.Writer, _ config.Path, _ config.CtxMap) {
	config.WriteString(dst, revSample)
}

func (cfg *RevCacheConf) ConfigName() string {
	return "rev_cache"
}

func (cfg *RevCacheConf) validateBackend() error {
	switch cfg.Backend() {
	case BackendSqlite, BackendMem:
		return nil
	case BackendNone:
		return serrors.New("No backend set")
	}
	return common.NewBasicError("Unsupported backend", nil, "backend", cfg.Backend())
}

func (cfg *RevCacheConf) validateConnection() error {
	if cfg.Backend() != BackendMem && cfg.Connection() == "" {
		return serrors.New("Empty connection not allowed")
	}
	return nil
}

// NewPathStorage creates a PathStorage from the given configs. Periodic
// cleaners for the given databases have to be manually created and started
// (see cleaner package).
func NewPathStorage(pdbConf PathDBConf) (pathdb.PathDB, revcache.RevCache, error) {

	if err := pdbConf.Validate(); err != nil {
		return nil, nil, common.NewBasicError("Invalid pathdb config", err)
	}
	pdb, err := newPathDB(pdbConf)
	if err != nil {
		return nil, nil, err
	}
	rc, err := newRevCache(pdbConf)
	if err != nil {
		return nil, nil, err
	}
	return pdb, rc, nil
}

func newPathDB(conf PathDBConf) (pathdb.PathDB, error) {
	log.Info("Connecting PathDB", "backend", conf.Backend(), "connection", conf.Connection())
	var err error
	var pdb pathdb.PathDB

	switch conf.Backend() {
	case BackendSqlite:
		pdb, err = sqlitepathdb.New(conf.Connection())
	case BackendNone:
		return nil, nil
	default:
		return nil, common.NewBasicError("Unsupported backend", nil, "backend", conf.Backend())
	}

	if err != nil {
		return nil, err
	}
	db.SetConnLimits(&conf, pdb)
	return pdb, nil
}

func newRevCache(conf PathDBConf) (revcache.RevCache, error) {
	switch conf.Backend() {
	case BackendSqlite:
		log.Info("Connecting RevCache", "backend", "memory")
		return memrevcache.New(), nil
	default:
		return nil, common.NewBasicError("Unsupported backend", nil, "backend", conf.Backend())
	}
}
