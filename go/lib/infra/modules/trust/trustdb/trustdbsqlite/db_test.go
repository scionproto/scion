// Copyright 2018 ETH Zurich, Anapaya Systems
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
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb/trustdbtest"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	ctxTimeout = time.Second
)

var _ trustdbtest.TestableTrustDB = (*TestTrustDB)(nil)

type TestTrustDB struct {
	*Backend
}

func (b *TestTrustDB) Prepare(t *testing.T, _ context.Context) {
	b.Backend = newDatabase(t)
}

func TestTrustDBSuite(t *testing.T) {
	tdb := &TestTrustDB{}
	Convey("TrustDBTestSuite", t, func() {
		trustdbtest.TestTrustDB(t, tdb)
	})
}

func newDatabase(t *testing.T) *Backend {
	db, err := New(":memory:")
	xtest.FailOnErr(t, err)
	return db
}
