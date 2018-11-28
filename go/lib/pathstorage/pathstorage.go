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
	"time"

	cache "github.com/patrickmn/go-cache"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	sqlitepathdb "github.com/scionproto/scion/go/lib/pathdb/sqlite"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/revcache/memrevcache"
)

type Backend string

const (
	BackendNone   Backend = ""
	BackendSqlite Backend = "sqlite"
	BackendMem    Backend = "mem"
)

// PathDBConf is the configuration for the connection to the path database.
type PathDBConf struct {
	Backend    Backend
	Connection string
}

// InitDefaults choses the sqlite backend if no backned is set.
func (c *PathDBConf) InitDefaults() {
	if c.Backend == BackendNone {
		c.Backend = BackendSqlite
	}
}

// Validate validates the configuration, should be called after InitDefaults.
func (c *PathDBConf) validate() error {
	if c.Backend == BackendNone {
		return common.NewBasicError("No backend set", nil)
	}
	if c.Connection == "" {
		return common.NewBasicError("Empty connection not allowed", nil)
	}
	return nil
}

// RevCacheConf is the configuration for the connection to the revocation cache.
type RevCacheConf struct {
	Backend    Backend
	Connection string
}

// InitDefaults chooses the in-memory backend if no backend is set.
func (c *RevCacheConf) InitDefaults() {
	if c.Backend == BackendNone {
		c.Backend = BackendMem
	}
}

// Validate validates the configuration, should be called after InitDefaults.
func (c *RevCacheConf) validate() error {
	if c.Backend == BackendNone {
		return common.NewBasicError("No backend set", nil)
	}
	if c.Backend != BackendMem && c.Connection == "" {
		return common.NewBasicError("Empty connection not allowed", nil)
	}
	return nil
}

// NewPathStorage creates a PathStorage from the given configs.
func NewPathStorage(pdbConf PathDBConf,
	rcConf RevCacheConf) (pathdb.PathDB, revcache.RevCache, error) {

	if err := pdbConf.validate(); err != nil {
		return nil, nil, common.NewBasicError("Invalid pathdb config", err)
	}
	if err := rcConf.validate(); err != nil {
		return nil, nil, common.NewBasicError("Invalid revcache config", err)
	}
	if sameBackend(pdbConf, rcConf) {
		return newCombinedBackend(pdbConf, rcConf)
	}
	pdb, err := newPathDB(pdbConf)
	if err != nil {
		return nil, nil, err
	}
	rc, err := newRevCache(rcConf)
	if err != nil {
		return nil, nil, err
	}
	return pdb, rc, nil
}

func sameBackend(pdbConf PathDBConf, rcConf RevCacheConf) bool {
	return pdbConf.Backend == rcConf.Backend && pdbConf.Backend != BackendNone
}

func newCombinedBackend(pdbConf PathDBConf,
	rcConf RevCacheConf) (pathdb.PathDB, revcache.RevCache, error) {

	panic("Combined backend not supported")
}

func newPathDB(conf PathDBConf) (pathdb.PathDB, error) {
	log.Info("Connecting PathDB", "backend", conf.Backend, "connection", conf.Connection)
	switch conf.Backend {
	case BackendSqlite:
		return sqlitepathdb.New(conf.Connection)
	case BackendNone:
		return nil, nil
	default:
		return nil, common.NewBasicError("Unsupported backend", nil, "backend", conf.Backend)
	}
}

func newRevCache(conf RevCacheConf) (revcache.RevCache, error) {
	log.Info("Connecting RevCache", "backend", conf.Backend, "connection", conf.Connection)
	switch conf.Backend {
	case BackendMem:
		return memrevcache.New(cache.NoExpiration, time.Second), nil
	case BackendNone:
		return nil, nil
	default:
		return nil, common.NewBasicError("Unsupported backend", nil, "backend", conf.Backend)
	}
}
