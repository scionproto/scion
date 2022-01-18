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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	beaconlib "github.com/scionproto/scion/go/cs/beacon"
	dbtest "github.com/scionproto/scion/go/cs/beacon/beacondbtest"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/pkg/storage"
	"github.com/scionproto/scion/go/pkg/storage/beacon"
)

var (
	timeout = time.Second
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
	t.Run("GetBeacons", func(t *testing.T) { testGetBeacons(t, db) })
	t.Run("DeleteExpired should delete expired segments", func(t *testing.T) {
		if _, ok := db.(interface{ IgnoreCleanable() }); ok {
			t.Skip("Ignoring beacon cleaning test")
		}

		ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelF()
		db.Prepare(t, ctx)

		ts1 := uint32(10)
		ts2 := uint32(20)
		// defaultExp is the default expiry of the hopfields.
		defaultExp := path.ExpTimeToDuration(63)
		dbtest.InsertBeacon(t, db, dbtest.Info3, 12, ts1, beaconlib.UsageProp)
		dbtest.InsertBeacon(t, db, dbtest.Info2, 13, ts2, beaconlib.UsageProp)
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

func testGetBeacons(t *testing.T, db TestableDB) {
	// Beacons in results are sorted from newest (3) to oldest (1).
	usages := []beaconlib.Usage{
		beaconlib.UsageDownReg,
		beaconlib.UsageUpReg,
		beaconlib.UsageCoreReg | beaconlib.UsageUpReg,
	}
	var results []beacon.Beacon
	for i, info := range [][]dbtest.IfInfo{dbtest.Info4, dbtest.Info2, dbtest.Info3} {
		b, _ := dbtest.AllocBeacon(t, info, uint16(i), uint32(i+1))
		results = append(results, beacon.Beacon{Beacon: b, Usage: usages[i]})
	}
	insertBeacons := func(t *testing.T, db beaconlib.DB) {
		// reverse order because GetBeacons returns values LIFO by default
		for i := len(results) - 1; i >= 0; i-- {
			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			_, err := db.InsertBeacon(ctx, results[i].Beacon, results[i].Usage)
			require.NoError(t, err)
		}
	}
	tests := map[string]struct {
		PrepareDB func(t *testing.T, ctx context.Context, db beaconlib.DB)
		Params    beacon.QueryParams
		Expected  []beacon.Beacon
	}{
		"Empty result on empty DB": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {},
			Expected:  []beacon.Beacon{},
		},
		"Returns all with zero params": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Expected: results,
		},
		"Empty result for non-existing SegID": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				SegIDs: [][]byte{[]byte("I don't existz")},
			},
			Expected: []beacon.Beacon{},
		},
		"Filter by existing SegID": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				SegIDs: [][]byte{results[0].Beacon.Segment.ID()},
			},
			Expected: results[:1],
		},
		"Filter by SegID prefixes": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				SegIDs: [][]byte{
					results[0].Beacon.Segment.ID()[:4],
					results[1].Beacon.Segment.ID()[:1],
				},
			},
			Expected: results[:2],
		},
		"Empty result for non-existing start IA": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				StartsAt: []addr.IA{addr.MustIAFrom(addr.MaxISD, 0)},
			},
			Expected: []beacon.Beacon{},
		},
		"Filter by existing start IA": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				StartsAt: []addr.IA{results[0].Beacon.Segment.FirstIA()},
			},
			Expected: results[:1],
		},
		"Filter by start IA with wildcard AS": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				StartsAt: []addr.IA{addr.MustIAFrom(results[0].Beacon.Segment.FirstIA().ISD(), 0)},
			},
			Expected: results[:1],
		},
		"Filter by start IA with wildcard ISD": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				StartsAt: []addr.IA{addr.MustIAFrom(0, results[0].Beacon.Segment.FirstIA().AS())},
			},
			Expected: results[:1],
		},
		"Filter by start IA with wildcards": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				StartsAt: []addr.IA{addr.MustIAFrom(0, 0)},
			},
			Expected: results,
		},
		"Filter by non-existing ingress interface ID": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				IngressInterfaces: []uint16{42},
			},
			Expected: []beacon.Beacon{},
		},
		"Filter by existing ingress interface ID": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				IngressInterfaces: []uint16{0},
			},
			Expected: results[:1],
		},
		"Filter by non-existing Usage": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				Usages: []beaconlib.Usage{beaconlib.UsageProp},
			},
			Expected: []beacon.Beacon{},
		},
		"Filter by existing Usage": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				Usages: []beaconlib.Usage{beaconlib.UsageUpReg},
			},
			Expected: results[1:],
		},
		"Filter by multiple Usages (intersection)": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				Usages: []beaconlib.Usage{beaconlib.UsageCoreReg | beaconlib.UsageUpReg},
			},
			Expected: results[2:],
		},
		"Filter by multiple Usages (union)": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				Usages: []beaconlib.Usage{beaconlib.UsageDownReg, beaconlib.UsageCoreReg},
			},
			Expected: []beacon.Beacon{results[0], results[2]},
		},
		"Filter by ValidAt before creation": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				ValidAt: time.Unix(0, 0),
			},
			Expected: []beacon.Beacon{},
		},
		"Filter by ValidAt after expiration": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				ValidAt: time.Unix(24*60*60, 0),
			},
			Expected: []beacon.Beacon{},
		},
		"Filter by ValidAt": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params: beacon.QueryParams{
				ValidAt: time.Unix(2, 0),
			},
			Expected: results[:2],
		},
		"ValidAt ignored if Zero": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beaconlib.DB) {
				insertBeacons(t, db)
			},
			Params:   beacon.QueryParams{},
			Expected: results,
		},
	}
	checkEqual := func(t *testing.T, expected []beacon.Beacon, actual []beacon.Beacon) {
		assert.Equal(t, len(expected), len(actual), "Results lengths")
		for i := range expected {
			dbtest.CheckResults(t,
				[]beaconlib.Beacon{expected[i].Beacon},
				[]beaconlib.Beacon{actual[i].Beacon},
			)
			assert.Equal(t, expected[i].Usage, actual[i].Usage, fmt.Sprint("Usage of index ", i))
			// Ignore differences in lastUpdated.
		}
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, ctx)
			test.PrepareDB(t, ctx, db)
			results, err := db.GetBeacons(ctx, &test.Params)
			require.NoError(t, err)
			checkEqual(t, test.Expected, results)
		})
	}
}
