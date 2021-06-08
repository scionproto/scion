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

package dbtest

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	beaconlib "github.com/scionproto/scion/go/cs/beacon"
	dbtest "github.com/scionproto/scion/go/cs/beacon/beacondbtest"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/pkg/storage"
	"github.com/scionproto/scion/go/pkg/storage/beacon"
)

// TestableDB extends the beacon db interface with methods that are needed for testing.
type TestableDB interface {
	storage.BeaconDB
	// We force all test implementations to implement cleanable. This ensures that we
	// explicitly have to opt-out of testing the clean-up functionality. This is a lot
	// safer than opting-in to testing it via interface smuggling.
	// To opt-out, simply define a "IgnoreCleanup" method on the type under test.
	beacon.Cleanable
	// Prepare should reset the internal state so that the db is empty and is ready to be tested.
	Prepare(*testing.T, context.Context)
}

// Run should be used to test any implementation of the storage.BeaconDB
// interface. An implementation interface should at least have one test method
// that calls this test-suite.
func Run(t *testing.T, db TestableDB) {
	dbtest.Test(t, db)
	run(t, db)
}

func run(t *testing.T, db TestableDB) {
	t.Run("DeleteExpired should delete expired segments", func(t *testing.T) {
		if _, ok := db.(interface{ IgnoreCleanable() }); ok {
			t.Skip("Ignoring beacon cleaning test")
		}

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelF()
		db.Prepare(t, ctx)

		ts1 := uint32(10)
		ts2 := uint32(20)
		// defaultExp is the default expiry of the hopfields.
		defaultExp := path.ExpTimeToDuration(63)
		dbtest.InsertBeacon(t, ctrl, db, dbtest.Info3, 12, ts1, beaconlib.UsageProp)
		dbtest.InsertBeacon(t, ctrl, db, dbtest.Info2, 13, ts2, beaconlib.UsageProp)
		// No expired beacon
		deleted, err := db.DeleteExpiredBeacons(ctx, time.Unix(10, 0).Add(defaultExp))
		require.NoError(t, err)
		assert.Equal(t, 0, deleted, "Deleted")
		// 1 expired
		deleted, err = db.DeleteExpiredBeacons(ctx, time.Unix(20, 0).Add(defaultExp))
		require.NoError(t, err)
		assert.Equal(t, 1, deleted, "Deleted")
		// 1 expired
		deleted, err = db.DeleteExpiredBeacons(ctx, time.Unix(30, 0).Add(defaultExp))
		require.NoError(t, err)
		assert.Equal(t, 1, deleted, "Deleted")
	})
}
