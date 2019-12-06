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

package trustdbsqlite

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/infra/modules/trust/v2/trustdbtest"
)

var _ trustdbtest.TestableTrustDB = (*TestTrustDB)(nil)

type TestTrustDB struct {
	*Backend
}

func (b *TestTrustDB) Prepare(t *testing.T, _ context.Context) {
	b.Backend = newDatabase(t)
}

func TestTrustDBSuite(t *testing.T) {
	trustdbtest.TestTrustDB(t, &TestTrustDB{})
}

func newDatabase(t *testing.T) *Backend {
	db, err := New(":memory:")
	require.NoError(t, err)
	return db
}
