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
	"github.com/scionproto/scion/go/lib/pathdb"
	sqlitepathdb "github.com/scionproto/scion/go/lib/pathdb/sqlite"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/revcache/memrevcache"
)

type Backend string

const (
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
	if c.Backend == "" {
		c.Backend = BackendSqlite
	}
}

// NewPathDB returns a PathDB for the given config.
// In case an invalid backend is requested an error is returned.
func NewPathDB(conf PathDBConf) (pathdb.PathDB, error) {
	switch conf.Backend {
	case BackendSqlite:
		return sqlitepathdb.New(conf.Connection)
	default:
		return nil, common.NewBasicError("Unsupported backend", nil, "backend", conf.Backend)
	}
}

// RevCacheConf is the configuration for the connection to the revocation cache.
type RevCacheConf struct {
	Backend    Backend
	Connection string
}

// InitDefaults chooses the in-memory backend if no backend is set.
func (c *RevCacheConf) InitDefaults() {
	if c.Backend == "" {
		c.Backend = BackendMem
	}
}

// NewRevCache returns a RevCache for the given config.
// In case an invalid backend is requested an error is returned.
func NewRevCache(conf RevCacheConf) (revcache.RevCache, error) {
	switch conf.Backend {
	case BackendMem:
		return memrevcache.New(cache.NoExpiration, time.Second), nil
	default:
		return nil, common.NewBasicError("Unsupported backend", nil, "backend", conf.Backend)
	}
}
