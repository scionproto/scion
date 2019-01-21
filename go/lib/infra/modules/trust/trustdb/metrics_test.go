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

func TestFunctionalityWorks(t *testing.T) {
	setup := func() trustdb.TrustDB {
		return newDatabase(t)
	}
	cleanup := func(db trustdb.TrustDB) {
		db.Close()
	}
	Convey("TestMetricsWrapper functions normally", t, func() {
		trustdbtest.TestTrustDB(t, setup, cleanup)
	})
}

func newDatabase(t *testing.T) trustdb.TrustDB {
	db, err := trustdbsqlite.New(":memory:")
	xtest.FailOnErr(t, err)
	return trustdb.WithMetrics("testdb", db)
}
