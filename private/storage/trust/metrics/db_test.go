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

package metrics_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/storage/db"
	"github.com/scionproto/scion/private/storage/trust/dbtest"
	"github.com/scionproto/scion/private/storage/trust/metrics"
	"github.com/scionproto/scion/private/storage/trust/sqlite"
)

type DB struct {
	storage.TrustDB
}

func (b *DB) Prepare(t *testing.T, _ context.Context) {
	b.TrustDB = newDatabase(t)
}

func TestDB(t *testing.T) {
	dbtest.Run(t, &DB{}, dbtest.Config{})
}

func newDatabase(t *testing.T) storage.TrustDB {
	db, err := sqlite.New(
		xtest.SanitizedName(t),
		&db.SqliteConfig{InMemory: true},
	)
	require.NoError(t, err)
	return metrics.WrapDB(db, metrics.Config{
		Driver:       "mem-sqlite",
		QueriesTotal: nil,
	})
}
