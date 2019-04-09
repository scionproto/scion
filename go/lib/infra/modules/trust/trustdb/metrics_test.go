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

package trustdb_test

import (
	"context"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb/trustdbsqlite"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb/trustdbtest"
	"github.com/scionproto/scion/go/lib/xtest"
)

func init() {
	trustdbtest.TestDataRelPath = "trustdbtest/testdata"
}

type TestTrustDB struct {
	trustdb.TrustDB
}

func (b *TestTrustDB) Prepare(t *testing.T, _ context.Context) {
	b.TrustDB = newDatabase(t)
}

func TestFunctionalityWorks(t *testing.T) {
	tdb := &TestTrustDB{}
	Convey("TestMetricsWrapper functions normally", t, func() {
		trustdbtest.TestTrustDB(t, tdb)
	})
}

func newDatabase(t *testing.T) trustdb.TrustDB {
	db, err := trustdbsqlite.New(":memory:")
	xtest.FailOnErr(t, err)
	return trustdb.WithMetrics("testdb", db)
}
