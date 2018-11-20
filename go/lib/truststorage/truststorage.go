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

package truststorage

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb/trustdbsqlite"
)

type Backend string

const (
	BackendNone   Backend = ""
	BackendSqlite Backend = "sqlite"
)

// TrustDBConf is the configuration for the connection to the trust database.
type TrustDBConf struct {
	Backend    Backend
	Connection string
}

// InitDefaults initializes the default values for the config.
func (c *TrustDBConf) InitDefaults() {
	if c.Backend == BackendNone {
		c.Backend = BackendSqlite
	}
}

// New creates a TrustDB for the given config.
func New(conf TrustDBConf) (trustdb.TrustDB, error) {

	switch conf.Backend {
	case BackendSqlite:
		return trustdbsqlite.New(conf.Connection)
	default:
		return nil, common.NewBasicError("Unsupported backend", nil, "backend", conf.Backend)
	}
}
