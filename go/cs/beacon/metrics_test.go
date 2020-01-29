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

package beacon_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beacon/beacondbsqlite"
	"github.com/scionproto/scion/go/cs/beacon/beacondbtest"
	"github.com/scionproto/scion/go/lib/xtest"
)

var testIA = xtest.MustParseIA("1-ff00:0:333")

var _ beacondbtest.Testable = (*TestBackend)(nil)

type TestBackend struct {
	beacon.DB
}

func (b *TestBackend) Prepare(t *testing.T, _ context.Context) {
	db, err := beacondbsqlite.New("file::memory:", testIA)
	require.NoError(t, err)
	b.DB = beacon.DBWithMetrics("testdb", db)
}

func TestBeaconDBSuite(t *testing.T) {
	tdb := &TestBackend{}
	beacondbtest.Test(t, tdb)
}
