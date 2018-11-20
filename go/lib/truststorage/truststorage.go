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

// Package truststorage provides a "factory" for trust database.
// A config containing the backend type and the connection string
// are used to create a specific trust db.
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
	// Backend is the type of backend for this db. If empty (BackendNone) the default is selected.
	Backend    Backend
	Connection string
}

// New creates a TrustDB from the config.
func (c TrustDBConf) New() (trustdb.TrustDB, error) {
	switch c.Backend {
	case BackendSqlite:
		return trustdbsqlite.New(c.Connection)
	case BackendNone:
		return defaultBackend(c.Connection)
	default:
		return nil, common.NewBasicError("Unsupported backend", nil, "backend", c.Backend)
	}
}

func defaultBackend(connection string) (trustdb.TrustDB, error) {
	return trustdbsqlite.New(connection)
}
