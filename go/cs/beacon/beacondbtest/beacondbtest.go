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

package beacondbtest

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/proto"
)

var (
	signer = graph.NewSigner()

	ia311 = addr.IA{I: 1, A: 0xff0000000311}
	ia330 = addr.IA{I: 1, A: 0xff0000000330}
	ia331 = addr.IA{I: 1, A: 0xff0000000331}
	ia332 = addr.IA{I: 1, A: 0xff0000000332}
	ia333 = addr.IA{I: 1, A: 0xff0000000333}

	Info1 = []IfInfo{
		{
			IA:     ia311,
			Next:   ia330,
			Egress: 10,
		},
	}

	Info2 = []IfInfo{
		{
			IA:     ia330,
			Next:   ia331,
			Egress: 4,
		},
		{
			IA:      ia331,
			Next:    ia332,
			Ingress: 1,
			Egress:  4,
			Peers:   []PeerEntry{{IA: ia311, Ingress: 4}},
		},
	}

	Info3 = []IfInfo{
		{
			IA:     ia330,
			Next:   ia331,
			Egress: 5,
		},
		{
			IA:      ia331,
			Next:    ia332,
			Ingress: 2,
			Egress:  3,
			Peers:   []PeerEntry{{IA: ia311, Ingress: 6}},
		},
		{
			IA:      ia332,
			Next:    ia333,
			Ingress: 1,
			Egress:  7,
		},
	}

	timeout = 3 * time.Second
)

// Testable extends the beacon db interface with methods that are needed for
// testing.
type Testable interface {
	beacon.DB
	// Prepare should reset the internal state so that the DB is empty and is
	// ready to be tested.
	Prepare(t *testing.T, ctx context.Context)
}

// Test should be used to test any implementation of the BeaconDB interface. An
// implementation of the BeaconDB interface should at least have one test
// method that calls this test-suite.
func Test(t *testing.T, db Testable) {
	testWrapper := func(test func(*testing.T, *gomock.Controller,
		beacon.DBReadWrite)) func(t *testing.T) {

		return func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			prepareCtx, cancelF := context.WithTimeout(context.Background(), 2*timeout)
			defer cancelF()
			db.Prepare(t, prepareCtx)
			test(t, ctrl, db)
		}
	}
	tableWrapper := func(inTx bool, test func(*testing.T, Testable, bool)) func(t *testing.T) {
		return func(t *testing.T) {
			test(t, db, inTx)
		}
	}
	t.Run("BeaconSources should report all sources",
		testWrapper(testBeaconSources))
	t.Run("InsertBeacon should correctly insert a new beacon",
		testWrapper(testInsertBeacon))
	t.Run("InsertBeacon should correctly update a new beacon",
		testWrapper(testUpdateExisting))
	t.Run("InsertBeacon should correctly ignore an older beacon",
		testWrapper(testUpdateOlderIgnored))
	t.Run("CandidateBeacons returns the expected beacons",
		tableWrapper(false, testCandidateBeacons))
	t.Run("DeleteExpired should delete expired segments",
		testWrapper(testDeleteExpiredBeacons))
	t.Run("DeleteRevokedBeacons",
		tableWrapper(false, testDeleteRevokedBeacons))
	t.Run("AllRevocations",
		tableWrapper(false, testAllRevocations))
	t.Run("InsertRevocation updates existing rev",
		testWrapper(testInsertUpdateRevocation))
	t.Run("DeleteRevocations should delete revocations",
		tableWrapper(false, testDeleteRevocation2))
	t.Run("DeleteExpiredRevocations should delete expired revocations",
		testWrapper(testDeleteExpiredRevocations))
	txTestWrapper := func(test func(*testing.T, *gomock.Controller,
		beacon.DBReadWrite)) func(t *testing.T) {

		return func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, ctx)
			tx, err := db.BeginTransaction(ctx, nil)
			require.NoError(t, err)
			test(t, ctrl, tx)
			err = tx.Commit()
			require.NoError(t, err)
		}
	}
	t.Run("WithTransaction", func(t *testing.T) {
		t.Run("BeaconSources should report all sources",
			txTestWrapper(testBeaconSources))
		t.Run("InsertBeacon should correctly insert a new beacon",
			txTestWrapper(testInsertBeacon))
		t.Run("InsertBeacon should correctly update a new beacon",
			txTestWrapper(testUpdateExisting))
		t.Run("InsertBeacon should correctly ignore an older beacon",
			txTestWrapper(testUpdateOlderIgnored))
		t.Run("CandidateBeacons returns the expected beacons",
			tableWrapper(true, testCandidateBeacons))
		t.Run("DeleteExpired should delete expired segments",
			txTestWrapper(testDeleteExpiredBeacons))
		t.Run("DeleteRevokedBeacons",
			tableWrapper(true, testDeleteRevokedBeacons))
		t.Run("AllRevocations",
			tableWrapper(true, testAllRevocations))
		t.Run("InsertRevocation updates existing rev",
			txTestWrapper(testInsertUpdateRevocation))
		t.Run("DeleteRevocations should delete revocations",
			tableWrapper(true, testDeleteRevocation2))
		t.Run("DeleteExpiredRevocations should delete expired revocations",
			txTestWrapper(testDeleteExpiredRevocations))
		t.Run("Test transaction rollback", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			prepareCtx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, prepareCtx)
			testRollback(t, ctrl, db)
		})
	})
}

func testBeaconSources(t *testing.T, ctrl *gomock.Controller, db beacon.DBReadWrite) {
	for i, info := range [][]IfInfo{Info3, Info2, Info1} {
		InsertBeacon(t, ctrl, db, info, 12, uint32(i), beacon.UsageProp)
	}
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	ias, err := db.BeaconSources(ctx)
	require.NoError(t, err)
	assert.ElementsMatch(t, []addr.IA{ia311, ia330}, ias)
}

func testInsertBeacon(t *testing.T, ctrl *gomock.Controller, db beacon.DBReadWrite) {
	TS := uint32(10)
	b, _ := AllocBeacon(t, ctrl, Info3, 12, TS)

	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	inserted, err := db.InsertBeacon(ctx, b, beacon.UsageProp)
	require.NoError(t, err)
	exp := beacon.InsertStats{Inserted: 1, Updated: 0}
	assert.Equal(t, exp, inserted)
	// Fetch the candidate beacons
	results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, addr.IA{})
	require.NoError(t, err)
	// There should only be one candidate beacon, and it should match the inserted.
	CheckResult(t, results, b)
	for _, usage := range []beacon.Usage{beacon.UsageUpReg, beacon.UsageDownReg,
		beacon.UsageCoreReg} {
		results, err = db.CandidateBeacons(ctx, 10, usage, addr.IA{})
		CheckEmpty(t, usage.String(), results, err)
	}
}

func testUpdateExisting(t *testing.T, ctrl *gomock.Controller, db beacon.DBReadWrite) {
	oldTS := uint32(10)
	oldB, oldId := AllocBeacon(t, ctrl, Info3, 12, oldTS)

	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	inserted, err := db.InsertBeacon(ctx, oldB, beacon.UsageProp)
	require.NoError(t, err)
	exp := beacon.InsertStats{Inserted: 1, Updated: 0}
	assert.Equal(t, exp, inserted)
	newTS := uint32(20)
	newB, newId := AllocBeacon(t, ctrl, Info3, 12, newTS)
	assert.Equal(t, oldId, newId, "IDs should match")
	inserted, err = db.InsertBeacon(ctx, newB, beacon.UsageDownReg)
	require.NoError(t, err)
	exp = beacon.InsertStats{Inserted: 0, Updated: 1}
	assert.Equal(t, exp, inserted)
	// Fetch the candidate beacons
	results, err := db.CandidateBeacons(ctx, 10, beacon.UsageDownReg, addr.IA{})
	require.NoError(t, err, "CandidateBeacons err")
	// There should only be one candidate beacon, and it should match the inserted.
	CheckResult(t, results, newB)
	for _, usage := range []beacon.Usage{beacon.UsageUpReg, beacon.UsageProp,
		beacon.UsageCoreReg} {
		results, err = db.CandidateBeacons(ctx, 10, usage, addr.IA{})
		CheckEmpty(t, usage.String(), results, err)
	}
}

func testUpdateOlderIgnored(t *testing.T, ctrl *gomock.Controller, db beacon.DBReadWrite) {
	newTS := uint32(20)
	newB, newId := AllocBeacon(t, ctrl, Info3, 12, newTS)

	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	inserted, err := db.InsertBeacon(ctx, newB, beacon.UsageProp)
	require.NoError(t, err)
	exp := beacon.InsertStats{Inserted: 1, Updated: 0}
	assert.Equal(t, exp, inserted, "Inserted new")
	oldTS := uint32(10)
	oldB, oldId := AllocBeacon(t, ctrl, Info3, 12, oldTS)
	assert.Equal(t, oldId, newId, "IDs should match")
	inserted, err = db.InsertBeacon(ctx, oldB, beacon.UsageDownReg)
	require.NoError(t, err)

	exp = beacon.InsertStats{Inserted: 0, Updated: 0}
	assert.Equal(t, exp, inserted, "Inserted old")
	// Fetch the candidate beacons
	results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, addr.IA{})
	require.NoError(t, err)
	// There should only be one candidate beacon, and it should match the inserted.
	CheckResult(t, results, newB)
	for _, usage := range []beacon.Usage{beacon.UsageUpReg, beacon.UsageDownReg,
		beacon.UsageCoreReg} {
		results, err = db.CandidateBeacons(ctx, 10, usage, addr.IA{})
		CheckEmpty(t, usage.String(), results, err)
	}
}

func testCandidateBeacons(t *testing.T, db Testable, inTx bool) {
	rootCtrl := gomock.NewController(t)
	defer rootCtrl.Finish()
	// Insert beacons from longest to shortest path such that the insertion
	// order is not sorted the same as the expected outcome.
	var beacons []beacon.Beacon
	insertBeacons := func(t *testing.T, db beacon.DBReadWrite) {
		for i, info := range [][]IfInfo{Info3, Info2, Info1} {
			b := InsertBeacon(t, rootCtrl, db, info, 12, uint32(i), beacon.UsageProp)
			// Prepend to get beacons sorted from shortest to longest path.
			beacons = append([]beacon.Beacon{b}, beacons...)
		}
	}
	insertBeacons(t, db)
	tests := map[string]struct {
		PrepareDB func(t *testing.T, ctx context.Context, db beacon.DBReadWrite)
		Src       addr.IA
		Expected  []beacon.Beacon
	}{
		"If no source ISD-AS is specified, all beacons are returned": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beacon.DBReadWrite) {
				insertBeacons(t, db)
			},
			Expected: beacons,
		},
		"Only beacons with matching source ISD-AS are returned, if specified": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beacon.DBReadWrite) {
				insertBeacons(t, db)
			},
			Src:      beacons[0].Segment.FirstIA(),
			Expected: []beacon.Beacon{beacons[0]},
		},
		"Revoked beacons are not returned": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beacon.DBReadWrite) {
				insertBeacons(t, db)
				sRev, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
					IfID:         Info3[2].Ingress,
					RawIsdas:     Info3[2].IA.IAInt(),
					LinkType:     proto.LinkType_child,
					RawTimestamp: util.TimeToSecs(time.Now().Add(-5 * time.Second)),
					RawTTL:       10,
				})
				require.NoError(t, err)
				InsertRevocation(t, db, sRev)
			},
			// last beacon (info3) is revoked
			Expected: beacons[:2],
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			db.Prepare(t, ctx)

			test.PrepareDB(t, ctx, db)
			results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, test.Src)
			require.NoError(t, err)
			CheckResults(t, results, test.Expected)
		})
	}
}

func testDeleteExpiredBeacons(t *testing.T, ctrl *gomock.Controller, db beacon.DBReadWrite) {
	ts1 := uint32(10)
	ts2 := uint32(20)
	// defaultExp is the default expiry of the hopfields.
	defaultExp := path.ExpTimeToDuration(63)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	InsertBeacon(t, ctrl, db, Info3, 12, ts1, beacon.UsageProp)
	InsertBeacon(t, ctrl, db, Info2, 13, ts2, beacon.UsageProp)
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
}

func testDeleteRevokedBeacons(t *testing.T, db Testable, inTx bool) {
	rootCtrl := gomock.NewController(t)
	defer rootCtrl.Finish()

	ts := uint32(10)
	now := time.Unix(int64(ts)+2, 0)
	b3 := InsertBeacon(t, rootCtrl, db, Info3, 12, ts, beacon.UsageProp)
	b2 := InsertBeacon(t, rootCtrl, db, Info2, 13, ts, beacon.UsageProp)
	srev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
		IfID:         Info3[2].Ingress,
		RawIsdas:     Info3[2].IA.IAInt(),
		LinkType:     proto.LinkType_child,
		RawTimestamp: ts,
		RawTTL:       10,
	})
	require.NoError(t, err)
	srev2, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
		IfID:         Info2[1].Ingress,
		RawIsdas:     Info2[1].IA.IAInt(),
		LinkType:     proto.LinkType_child,
		RawTimestamp: ts,
		RawTTL:       10,
	})
	require.NoError(t, err)

	tests := map[string]struct {
		PrepareDB       func(t *testing.T, ctx context.Context, db beacon.DBReadWrite)
		ExpectedDeleted int
		ExpectedBeacons []beacon.Beacon
	}{
		"DeleteRevokedBeacons with no revocations should not delete anything": {
			PrepareDB:       func(t *testing.T, ctx context.Context, db beacon.DBReadWrite) {},
			ExpectedBeacons: []beacon.Beacon{b2, b3},
		},
		"DeleteRevokedBeacon with revocation on one beacon should delete it": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beacon.DBReadWrite) {
				InsertRevocation(t, db, srev1)
			},
			ExpectedDeleted: 1,
			ExpectedBeacons: []beacon.Beacon{b2},
		},
		"DeleteRevokedBeacon with revocation on both beacons should delete both": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beacon.DBReadWrite) {
				InsertRevocation(t, db, srev1)
				InsertRevocation(t, db, srev2)
			},
			ExpectedDeleted: 2,
			ExpectedBeacons: []beacon.Beacon{},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, ctx)
			// reinsert b3 and b2 since the prepare above deletes them.
			InsertBeacon(t, rootCtrl, db, Info3, 12, ts, beacon.UsageProp)
			InsertBeacon(t, rootCtrl, db, Info2, 13, ts, beacon.UsageProp)

			test.PrepareDB(t, ctx, db)
			var deleted int
			if inTx {
				tx, err := db.BeginTransaction(ctx, nil)
				require.NoError(t, err)
				deleted, err = tx.DeleteRevokedBeacons(ctx, now)
				require.NoError(t, err)
				require.NoError(t, tx.Commit())
			} else {
				var err error
				deleted, err = db.DeleteRevokedBeacons(ctx, now)
				require.NoError(t, err)
			}
			assert.Equal(t, test.ExpectedDeleted, deleted)
			results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, addr.IA{})
			require.NoError(t, err)
			CheckResults(t, results, test.ExpectedBeacons)
		})
	}
}

func testAllRevocations(t *testing.T, db Testable, inTx bool) {
	ts := util.TimeToSecs(time.Now().Add(-5 * time.Second))
	srev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
		IfID:         Info3[2].Ingress,
		RawIsdas:     Info3[2].IA.IAInt(),
		LinkType:     proto.LinkType_child,
		RawTimestamp: ts,
		RawTTL:       10,
	})
	require.NoError(t, err)

	tests := map[string]struct {
		PrepareDB    func(t *testing.T, ctx context.Context, db beacon.DBReadWrite)
		ExpectedRevs []*path_mgmt.SignedRevInfo
	}{
		"AllRevocations on empty db should return an empty channel": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beacon.DBReadWrite) {},
		},
		"AllRevocations returns revocations in db": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beacon.DBReadWrite) {
				InsertRevocation(t, db, srev1)
			},
			ExpectedRevs: []*path_mgmt.SignedRevInfo{srev1},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, ctx)

			test.PrepareDB(t, ctx, db)
			if inTx {
				tx, err := db.BeginTransaction(ctx, nil)
				require.NoError(t, err)
				revs, err := tx.AllRevocations(ctx)
				require.NoError(t, err)
				CheckRevs(t, revs, test.ExpectedRevs)
				require.NoError(t, tx.Commit())
			} else {
				revs, err := db.AllRevocations(ctx)
				require.NoError(t, err)
				CheckRevs(t, revs, test.ExpectedRevs)
			}
		})
	}
}

func testInsertUpdateRevocation(t *testing.T, _ *gomock.Controller, db beacon.DBReadWrite) {
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	ts := util.TimeToSecs(time.Now().Add(-5 * time.Second))
	srev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
		IfID:         Info3[2].Ingress,
		RawIsdas:     Info3[2].IA.IAInt(),
		LinkType:     proto.LinkType_child,
		RawTimestamp: ts,
		RawTTL:       20,
	})
	require.NoError(t, err)
	err = db.InsertRevocation(ctx, srev1)
	require.NoError(t, err)
	// insert newer revocation should override old one
	srev2, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
		IfID:         Info3[2].Ingress,
		RawIsdas:     Info3[2].IA.IAInt(),
		LinkType:     proto.LinkType_child,
		RawTimestamp: ts + 1,
		RawTTL:       10,
	})
	require.NoError(t, err)
	err = db.InsertRevocation(ctx, srev2)
	require.NoError(t, err)
	revs, err := db.AllRevocations(ctx)
	require.NoError(t, err)
	CheckRevs(t, revs, []*path_mgmt.SignedRevInfo{srev2})
	// older revocation should keep the newer one.
	err = db.InsertRevocation(ctx, srev1)
	require.NoError(t, err)
	revs, err = db.AllRevocations(ctx)
	require.NoError(t, err)
	CheckRevs(t, revs, []*path_mgmt.SignedRevInfo{srev2})
}

func testDeleteRevocation2(t *testing.T, db Testable, inTx bool) {
	ts := util.TimeToSecs(time.Now().Add(-5 * time.Second))

	srev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
		IfID:         Info3[2].Ingress,
		RawIsdas:     Info3[2].IA.IAInt(),
		LinkType:     proto.LinkType_child,
		RawTimestamp: ts,
		RawTTL:       10,
	})
	require.NoError(t, err)

	tests := map[string]struct {
		PrepareDB    func(t *testing.T, ctx context.Context, db beacon.DBReadWrite)
		Delete       func(ctx context.Context, db beacon.DBReadWrite) error
		ExpectedRevs []*path_mgmt.SignedRevInfo
	}{
		"Delete on empty db": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beacon.DBReadWrite) {},
			Delete: func(ctx context.Context, db beacon.DBReadWrite) error {
				return db.DeleteRevocation(ctx, Info3[2].IA, Info3[2].Ingress)
			},
		},
		"Deleting an existing revocation removes it": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beacon.DBReadWrite) {
				InsertRevocation(t, db, srev1)
			},
			Delete: func(ctx context.Context, db beacon.DBReadWrite) error {
				return db.DeleteRevocation(ctx, Info3[2].IA, Info3[2].Ingress)
			},
		},
		"Deleting non-existing other revocation does not delete existing": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beacon.DBReadWrite) {
				InsertRevocation(t, db, srev1)
			},
			Delete: func(ctx context.Context, db beacon.DBReadWrite) error {
				return db.DeleteRevocation(ctx, Info3[2].IA, Info3[2].Egress)
			},
			ExpectedRevs: []*path_mgmt.SignedRevInfo{srev1},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, ctx)

			test.PrepareDB(t, ctx, db)
			if inTx {
				tx, err := db.BeginTransaction(ctx, nil)
				require.NoError(t, err)
				err = test.Delete(ctx, tx)
				require.NoError(t, err)
				revs, err := tx.AllRevocations(ctx)
				require.NoError(t, err)
				CheckRevs(t, revs, test.ExpectedRevs)
				require.NoError(t, tx.Commit())
			} else {
				err := test.Delete(ctx, db)
				require.NoError(t, err)
				revs, err := db.AllRevocations(ctx)
				require.NoError(t, err)
				CheckRevs(t, revs, test.ExpectedRevs)
			}
		})
	}
}

func testDeleteExpiredRevocations(t *testing.T, _ *gomock.Controller, db beacon.DBReadWrite) {
	now := time.Now()
	ts := util.TimeToSecs(now.Add(-5 * time.Second))
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	// delete on empty should work
	cnt, err := db.DeleteExpiredRevocations(ctx, now)
	require.NoError(t, err)
	assert.Zero(t, cnt)
	revs, err := db.AllRevocations(ctx)
	CheckEmptyRevs(t, revs, err)
	// delete with non empty db:
	srev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
		IfID:         Info3[2].Ingress,
		RawIsdas:     Info3[2].IA.IAInt(),
		LinkType:     proto.LinkType_child,
		RawTimestamp: ts,
		RawTTL:       10,
	})
	require.NoError(t, err)
	InsertRevocation(t, db, srev1)
	// non-expired revocation is not deleted.
	cnt, err = db.DeleteExpiredRevocations(ctx, now)
	require.NoError(t, err)
	assert.Zero(t, cnt)
	revs, err = db.AllRevocations(ctx)
	require.NoError(t, err)
	CheckRevs(t, revs, []*path_mgmt.SignedRevInfo{srev1})
	// expired is deleted
	cnt, err = db.DeleteExpiredRevocations(ctx, now.Add(6*time.Second))
	require.NoError(t, err)
	assert.Equal(t, 1, cnt, "Deletion expected")
	revs, err = db.AllRevocations(ctx)
	CheckEmptyRevs(t, revs, err)
}

func testRollback(t *testing.T, ctrl *gomock.Controller, db beacon.DB) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	tx, err := db.BeginTransaction(ctx, nil)
	require.NoError(t, err)
	b, _ := AllocBeacon(t, ctrl, Info3, 12, uint32(10))
	inserted, err := tx.InsertBeacon(ctx, b, beacon.UsageProp)
	require.NoError(t, err)
	exp := beacon.InsertStats{Inserted: 1, Updated: 0}
	assert.Equal(t, exp, inserted, "Insert should succeed")
	err = tx.Rollback()
	require.NoError(t, err)
	results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, addr.IA{})
	CheckEmpty(t, beacon.UsageProp.String(), results, err)
}

// CheckResult checks that the expected beacon is returned in results, and
// that it is the only returned beacon
func CheckResult(t *testing.T, results <-chan beacon.BeaconOrErr, expected beacon.Beacon) {
	CheckResults(t, results, []beacon.Beacon{expected})
}

func CheckResults(t *testing.T, results <-chan beacon.BeaconOrErr,
	expectedBeacons []beacon.Beacon) {

	for i, expected := range expectedBeacons {
		select {
		case res := <-results:
			assert.NoError(t, res.Err, "Beacon %d err", i)
			require.NotNil(t, res.Beacon.Segment, "Beacon %d segment", i)
			// Make sure the segment is properly initialized.

			assert.Equal(t, expected.Segment.Info, res.Beacon.Segment.Info)
			assert.Equal(t, expected.Segment.MaxIdx(), res.Beacon.Segment.MaxIdx())
			for i := range expected.Segment.ASEntries {
				expected := seg.ASEntry{
					Extensions:  expected.Segment.ASEntries[i].Extensions,
					HopEntry:    expected.Segment.ASEntries[i].HopEntry,
					Local:       expected.Segment.ASEntries[i].Local,
					MTU:         expected.Segment.ASEntries[i].MTU,
					Next:        expected.Segment.ASEntries[i].Next,
					PeerEntries: expected.Segment.ASEntries[i].PeerEntries,
				}
				actual := seg.ASEntry{
					Extensions:  res.Beacon.Segment.ASEntries[i].Extensions,
					HopEntry:    res.Beacon.Segment.ASEntries[i].HopEntry,
					Local:       res.Beacon.Segment.ASEntries[i].Local,
					MTU:         res.Beacon.Segment.ASEntries[i].MTU,
					Next:        res.Beacon.Segment.ASEntries[i].Next,
					PeerEntries: res.Beacon.Segment.ASEntries[i].PeerEntries,
				}
				assert.Equal(t, expected, actual)
			}
			assert.Equal(t, expected.InIfId, res.Beacon.InIfId, "InIfId %d should match", i)
		case <-time.After(timeout):
			t.Fatalf("Beacon %d took too long", i)
		}
	}
	CheckEmpty(t, "", results, nil)
}

// CheckEmpty checks that no beacon is in the result channel.
func CheckEmpty(t *testing.T, name string, results <-chan beacon.BeaconOrErr, err error) {
	t.Helper()
	assert.NoError(t, err, name)
	res, more := <-results
	assert.False(t, more)
	assert.Zero(t, res)
}

func CheckRevs(t *testing.T, results <-chan beacon.RevocationOrErr,
	expectedRevs []*path_mgmt.SignedRevInfo) {

	for i, expected := range expectedRevs {
		select {
		case res := <-results:
			require.NoError(t, res.Err, fmt.Sprintf("Rev %d err", i))
			require.NotNil(t, res.Rev, fmt.Sprintf("Rev %d nil", i))
			// make sure revinfo is initialized so comparison works.
			_, err := res.Rev.RevInfo()
			require.NoError(t, err)
			assert.Equal(t, expected, res.Rev, fmt.Sprintf("Rev %d rev", i))
		case <-time.After(timeout):
			t.Fatalf("Rev %d took too long", i)
		}
	}
	CheckEmptyRevs(t, results, nil)
}

func CheckEmptyRevs(t *testing.T, results <-chan beacon.RevocationOrErr, err error) {
	t.Helper()
	assert.NoError(t, err)
	res, more := <-results
	assert.False(t, more)
	assert.Zero(t, res)
}

func InsertBeacon(t *testing.T, ctrl *gomock.Controller, db beacon.DBReadWrite, ases []IfInfo,
	inIfId common.IFIDType, infoTS uint32, allowed beacon.Usage) beacon.Beacon {
	b, _ := AllocBeacon(t, ctrl, ases, inIfId, infoTS)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	_, err := db.InsertBeacon(ctx, b, allowed)
	require.NoError(t, err)
	return b
}

func InsertRevocation(t *testing.T, db beacon.DBReadWrite, sRev *path_mgmt.SignedRevInfo) {
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	err := db.InsertRevocation(ctx, sRev)
	require.NoError(t, err)
}

type PeerEntry struct {
	IA      addr.IA
	Ingress common.IFIDType
}

type IfInfo struct {
	IA      addr.IA
	Next    addr.IA
	Ingress common.IFIDType
	Egress  common.IFIDType
	Peers   []PeerEntry
}

func AllocBeacon(t *testing.T, ctrl *gomock.Controller, ases []IfInfo, inIfId common.IFIDType,
	infoTS uint32) (beacon.Beacon, []byte) {

	entries := make([]seg.ASEntry, len(ases))
	for i, as := range ases {
		var mtu int
		if i != 0 {
			mtu = 1500
		}

		var peers []seg.PeerEntry
		for _, peer := range as.Peers {
			peers = append(peers, seg.PeerEntry{
				Peer:          peer.IA,
				PeerInterface: 1337,
				PeerMTU:       1500,
				HopField: seg.HopField{
					ExpTime:     63,
					ConsIngress: uint16(peer.Ingress),
					ConsEgress:  uint16(as.Egress),
					MAC:         bytes.Repeat([]byte{0xff}, 6),
				},
			})
		}
		entries[i] = seg.ASEntry{
			Local: as.IA,
			Next:  as.Next,
			MTU:   1500,
			HopEntry: seg.HopEntry{
				IngressMTU: mtu,
				HopField: seg.HopField{
					ExpTime:     63,
					ConsIngress: uint16(as.Ingress),
					ConsEgress:  uint16(as.Egress),
					MAC:         bytes.Repeat([]byte{0xff}, 6),
				},
			},
			PeerEntries: peers,
		}
	}

	// XXX(roosd): deterministic beacon needed.
	pseg, err := seg.CreateSegment(time.Unix(int64(infoTS), 0), 10)
	require.NoError(t, err)

	for _, entry := range entries {
		err := pseg.AddASEntry(context.Background(), entry, signer)
		require.NoError(t, err)
	}
	return beacon.Beacon{Segment: pseg, InIfId: inIfId}, pseg.ID()
}
