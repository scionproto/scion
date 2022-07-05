// Copyright 2021 ETH Zurich
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
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/private/storage/drkey/sv/dbtest"
	"github.com/scionproto/scion/private/storage/drkey/sv/metrics"
	"github.com/scionproto/scion/private/storage/drkey/sv/sqlite"
)

var _ dbtest.TestableDB = (*TestBackend)(nil)

type TestBackend struct {
	drkey.SecretValueDB
}

func (b *TestBackend) Prepare(t *testing.T, _ context.Context) {
	db := newSecretValueDatabase(t)
	b.SecretValueDB = metrics.SecretValueWithMetrics("testdb", db)
}

func TestSecretValueDBSuite(t *testing.T) {
	tdb := &TestBackend{}
	dbtest.TestDB(t, tdb)
}

func newSecretValueDatabase(t *testing.T) *sqlite.Backend {
	dir := t.TempDir()
	file, err := ioutil.TempFile(dir, "db-test-")
	require.NoError(t, err)
	name := file.Name()
	err = file.Close()
	require.NoError(t, err)
	db, err := sqlite.NewBackend(name)
	require.NoError(t, err)
	return db
}
