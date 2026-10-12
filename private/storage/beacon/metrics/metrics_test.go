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

package metrics_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/storage/beacon"
	"github.com/scionproto/scion/private/storage/beacon/dbtest"
	"github.com/scionproto/scion/private/storage/beacon/metrics"
	"github.com/scionproto/scion/private/storage/beacon/sqlite"
	"github.com/scionproto/scion/private/storage/db"
)

var testIA = addr.MustParseIA("1-ff00:0:333")

type TestBackend struct {
	storage.BeaconDB
	beacon.Cleanable
}

func (b *TestBackend) Prepare(t *testing.T, _ context.Context) {
	db, err := sqlite.New(
		xtest.SanitizedName(t),
		testIA,
		&db.SqliteConfig{InMemory: true},
	)
	require.NoError(t, err)
	b.BeaconDB = metrics.WrapDB(db, metrics.Config{
		Driver:       "mem-sqlite",
		QueriesTotal: nil,
	})
}

// IgnoreCleanable instructs the test to ignore testing the cleanup functionality.
func (b *TestBackend) IgnoreCleanable() {}

func TestBeaconDBSuite(t *testing.T) {
	tdb := &TestBackend{}
	dbtest.Run(t, tdb)
}
