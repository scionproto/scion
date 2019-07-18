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
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/ctrl/seg/mock_seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

var (
	ia311 = addr.IA{I: 1, A: 0xff0000000311}
	ia330 = addr.IA{I: 1, A: 0xff0000000330}
	ia331 = addr.IA{I: 1, A: 0xff0000000331}
	ia332 = addr.IA{I: 1, A: 0xff0000000332}

	Info1 = []IfInfo{
		{
			IA:     ia311,
			Egress: 10,
		},
	}

	Info2 = []IfInfo{
		{
			IA:     ia330,
			Egress: 4,
		},
		{
			IA:      ia331,
			Ingress: 1,
			Egress:  4,
			Peers:   []PeerEntry{{IA: ia311, Ingress: 4}},
		},
	}

	Info3 = []IfInfo{
		{
			IA:     ia330,
			Egress: 5,
		},
		{
			IA:      ia331,
			Ingress: 2,
			Egress:  3,
			Peers:   []PeerEntry{{IA: ia311, Ingress: 6}},
		},
		{
			IA:      ia332,
			Ingress: 1,
			Egress:  7,
		},
	}

	timeout = time.Second
)

// Testable extends the beacon db interface with methods that are needed for testing.
type Testable interface {
	beacon.DB
	// Prepare should reset the internal state so that the DB is empty and is ready to be tested.
	Prepare(t *testing.T, ctx context.Context)
}

// Test should be used to test any implementation of the BeaconDB interface.
// An implementation of the BeaconDB interface should at least have one test method that calls
// this test-suite. The calling test code should have a top level Convey block.
func Test(t *testing.T, db Testable) {
	testWrapper := func(test func(*testing.T, *gomock.Controller, beacon.DBReadWrite)) func() {
		return func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			prepareCtx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, prepareCtx)
			test(t, ctrl, db)
		}
	}
	Convey("BeaconSources", testWrapper(testBeaconSources))
	Convey("InsertBeacon", testWrapper(testInsertBeacon))
	Convey("UpdateBeacon", testWrapper(testUpdateExisting))
	Convey("IgnoreBeaconUpdate", testWrapper(testUpdateOlderIgnored))
	Convey("CandidateBeacons", testWrapper(testCandidateBeacons))
	Convey("DeleteExpiredBeacons", testWrapper(testDeleteExpiredBeacons))
	Convey("DeleteRevokedBeacons", testWrapper(testDeleteRevokedBeacons))
	Convey("AllRevocations", testWrapper(testAllRevocations))
	Convey("CandidateBeaconsWithRevs", testWrapper(testReadWithRevocations))
	Convey("DeleteRevocation", testWrapper(testDeleteRevocation))
	Convey("DeleteExpiredRevocations", testWrapper(testDeleteExpiredRevocations))
	txTestWrapper := func(test func(*testing.T, *gomock.Controller, beacon.DBReadWrite)) func() {
		return func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, ctx)
			tx, err := db.BeginTransaction(ctx, nil)
			xtest.FailOnErr(t, err)
			test(t, ctrl, tx)
			err = tx.Commit()
			xtest.FailOnErr(t, err)
		}
	}
	Convey("WithTransaction", func() {
		Convey("BeaconSources", txTestWrapper(testBeaconSources))
		Convey("InsertBeacon", txTestWrapper(testInsertBeacon))
		Convey("UpdateBeacon", txTestWrapper(testUpdateExisting))
		Convey("IgnoreBeaconUpdate", txTestWrapper(testUpdateOlderIgnored))
		Convey("CandidateBeacons", txTestWrapper(testCandidateBeacons))
		Convey("DeleteExpiredBeacons", txTestWrapper(testDeleteExpiredBeacons))
		Convey("DeleteRevokedBeacons", txTestWrapper(testDeleteRevokedBeacons))
		Convey("AllRevocations", txTestWrapper(testAllRevocations))
		Convey("CandidateBeaconsWithRevs", txTestWrapper(testReadWithRevocations))
		Convey("DeleteRevocation", txTestWrapper(testDeleteRevocation))
		Convey("DeleteExpiredRevocations", txTestWrapper(testDeleteExpiredRevocations))
		Convey("TestTransactionRollback", func() {
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
	Convey("BeaconSources should report all sources", func() {
		for i, info := range [][]IfInfo{Info3, Info2, Info1} {
			InsertBeacon(t, ctrl, db, info, 12, uint32(i), beacon.UsageProp)
		}
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		ias, err := db.BeaconSources(ctx)
		SoMsg("err", err, ShouldBeNil)
		sort.Slice(ias, func(i, j int) bool { return ias[i].A < ias[j].A })
		SoMsg("len", len(ias), ShouldEqual, 2)
		SoMsg("311", ias[0], ShouldResemble, ia311)
		SoMsg("330", ias[1], ShouldResemble, ia330)
	})
}

func testInsertBeacon(t *testing.T, ctrl *gomock.Controller, db beacon.DBReadWrite) {
	Convey("InsertBeacon should correctly insert a new beacon", func() {
		TS := uint32(10)
		b, _ := AllocBeacon(t, ctrl, Info3, 12, TS)

		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		inserted, err := db.InsertBeacon(ctx, b, beacon.UsageProp)
		SoMsg("Insert err", err, ShouldBeNil)
		SoMsg("Inserted", inserted, ShouldEqual, 1)
		// Fetch the candidate beacons
		results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, addr.IA{})
		SoMsg("CandidateBeacons err", err, ShouldBeNil)
		// There should only be one candidate beacon, and it should match the inserted.
		CheckResult(t, results, b)
		for _, usage := range []beacon.Usage{beacon.UsageUpReg, beacon.UsageDownReg,
			beacon.UsageCoreReg} {
			results, err = db.CandidateBeacons(ctx, 10, usage, addr.IA{})
			CheckEmpty(t, usage.String(), results, err)
		}
	})
}

func testUpdateExisting(t *testing.T, ctrl *gomock.Controller, db beacon.DBReadWrite) {
	Convey("InsertBeacon should correctly update a new beacon", func() {
		oldTS := uint32(10)
		oldB, oldId := AllocBeacon(t, ctrl, Info3, 12, oldTS)

		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		inserted, err := db.InsertBeacon(ctx, oldB, beacon.UsageProp)
		SoMsg("Insert old err", err, ShouldBeNil)
		SoMsg("Inserted old", inserted, ShouldEqual, 1)
		newTS := uint32(20)
		newB, newId := AllocBeacon(t, ctrl, Info3, 12, newTS)
		SoMsg("IDs should match", newId, ShouldResemble, oldId)
		inserted, err = db.InsertBeacon(ctx, newB, beacon.UsageDownReg)
		SoMsg("Insert new err", err, ShouldBeNil)
		SoMsg("Inserted new", inserted, ShouldEqual, 1)
		// Fetch the candidate beacons
		results, err := db.CandidateBeacons(ctx, 10, beacon.UsageDownReg, addr.IA{})
		SoMsg("CandidateBeacons err", err, ShouldBeNil)
		// There should only be one candidate beacon, and it should match the inserted.
		CheckResult(t, results, newB)
		for _, usage := range []beacon.Usage{beacon.UsageUpReg, beacon.UsageProp,
			beacon.UsageCoreReg} {
			results, err = db.CandidateBeacons(ctx, 10, usage, addr.IA{})
			CheckEmpty(t, usage.String(), results, err)
		}
	})
}

func testUpdateOlderIgnored(t *testing.T, ctrl *gomock.Controller, db beacon.DBReadWrite) {
	Convey("InsertBeacon should correctly ignore an older beacon", func() {
		newTS := uint32(20)
		newB, newId := AllocBeacon(t, ctrl, Info3, 12, newTS)

		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		inserted, err := db.InsertBeacon(ctx, newB, beacon.UsageProp)
		SoMsg("Insert new err", err, ShouldBeNil)
		SoMsg("Inserted new", inserted, ShouldEqual, 1)
		oldTS := uint32(10)
		oldB, oldId := AllocBeacon(t, ctrl, Info3, 12, oldTS)
		SoMsg("IDs should match", newId, ShouldResemble, oldId)
		inserted, err = db.InsertBeacon(ctx, oldB, beacon.UsageDownReg)
		SoMsg("Insert old err", err, ShouldBeNil)
		SoMsg("Inserted old", inserted, ShouldEqual, 0)
		// Fetch the candidate beacons
		results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, addr.IA{})
		SoMsg("CandidateBeacons err", err, ShouldBeNil)
		// There should only be one candidate beacon, and it should match the inserted.
		CheckResult(t, results, newB)
		for _, usage := range []beacon.Usage{beacon.UsageUpReg, beacon.UsageDownReg,
			beacon.UsageCoreReg} {
			results, err = db.CandidateBeacons(ctx, 10, usage, addr.IA{})
			CheckEmpty(t, usage.String(), results, err)
		}
	})
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
			SoMsg(fmt.Sprintf("Beacon %d err", i), res.Err, ShouldBeNil)
			SoMsg(fmt.Sprintf("Beacon %d segment", i), res.Beacon.Segment, ShouldNotBeNil)
			// Make sure the segment is properly initialized.
			_, err := res.Beacon.Segment.ID()
			xtest.FailOnErr(t, err)
			_, err = res.Beacon.Segment.FullId()
			xtest.FailOnErr(t, err)
			SoMsg(fmt.Sprintf("Segment %d should match", i), res.Beacon.Segment, ShouldResemble,
				expected.Segment)
			SoMsg(fmt.Sprintf("InIfId %d should match", i), res.Beacon.InIfId, ShouldEqual,
				expected.InIfId)
		case <-time.After(timeout):
			t.Fatalf("Beacon %d took too long", i)
		}
	}
	select {
	case _, more := <-results:
		SoMsg("Channel should be empty", more, ShouldBeFalse)
	case <-time.After(timeout):
		t.Fatalf("Channel should have been closed but seems to be open still")
	}
}

// CheckEmpty checks that no beacon is in the result channel.
func CheckEmpty(t *testing.T, name string, results <-chan beacon.BeaconOrErr, err error) {
	SoMsg(name+" err", err, ShouldBeNil)
	for res := range results {
		// If we end up in this execution tree, the test failed.
		SoMsg("Found beacon "+name, res, ShouldBeFalse)
	}
}

func CheckRevs(t *testing.T, results <-chan beacon.RevocationOrErr,
	expectedRevs []*path_mgmt.SignedRevInfo) {

	for i, expected := range expectedRevs {
		select {
		case res := <-results:
			SoMsg(fmt.Sprintf("Rev %d err", i), res.Err, ShouldBeNil)
			// make sure revinfo is initialized so comparison works.
			_, err := res.Rev.RevInfo()
			xtest.FailOnErr(t, err)
			SoMsg(fmt.Sprintf("Rev %d rev", i), res.Rev, ShouldResemble, expected)
		case <-time.After(timeout):
			t.Fatalf("Rev %d took too long", i)
		}
	}
	select {
	case _, more := <-results:
		SoMsg("Channel should be empty", more, ShouldBeFalse)
	case <-time.After(timeout):
		t.Fatalf("Channel should have been closed but seems to be open still")
	}
}

func CheckEmptyRevs(t *testing.T, results <-chan beacon.RevocationOrErr, err error) {
	SoMsg("Err", err, ShouldBeNil)
	for range results {
		// If we end up in this execution tree, the test failed.
		t.Fatalf("Found revocation none expected")
	}
}

func testCandidateBeacons(t *testing.T, ctrl *gomock.Controller, db beacon.DBReadWrite) {
	Convey("CandidateBeacons returns the expected beacons", func() {
		// Insert beacons from longest to shortest path such that the insertion
		// order is not sorted the same as the expected outcome.
		var beacons []beacon.Beacon
		for i, info := range [][]IfInfo{Info3, Info2, Info1} {
			b := InsertBeacon(t, ctrl, db, info, 12, uint32(i), beacon.UsageProp)
			// Prepend to get beacons sorted from shortest to longest path.
			beacons = append([]beacon.Beacon{b}, beacons...)
		}
		Convey("If no source ISD-AS is specified, all beacons are returned", func() {
			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, addr.IA{})
			SoMsg("Err", err, ShouldBeNil)
			CheckResults(t, results, beacons)
		})
		Convey("Only beacons with matching source ISD-AS are returned, if specified", func() {
			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp,
				beacons[0].Segment.FirstIA())
			SoMsg("Err", err, ShouldBeNil)
			CheckResult(t, results, beacons[0])

		})
	})
}

func testDeleteExpiredBeacons(t *testing.T, ctrl *gomock.Controller, db beacon.DBReadWrite) {
	Convey("DeleteExpired should delete expired segments", func() {
		ts1 := uint32(10)
		ts2 := uint32(20)
		// defaultExp is the default expiry of the hopfields.
		defaultExp := spath.DefaultHopFExpiry.ToDuration()
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		InsertBeacon(t, ctrl, db, Info3, 12, ts1, beacon.UsageProp)
		InsertBeacon(t, ctrl, db, Info2, 13, ts2, beacon.UsageProp)
		deleted, err := db.DeleteExpiredBeacons(ctx, time.Unix(10, 0).Add(defaultExp))
		xtest.FailOnErr(t, err)
		SoMsg("Deleted", deleted, ShouldEqual, 0)
		deleted, err = db.DeleteExpiredBeacons(ctx, time.Unix(20, 0).Add(defaultExp))
		xtest.FailOnErr(t, err)
		SoMsg("Deleted", deleted, ShouldEqual, 1)
		deleted, err = db.DeleteExpiredBeacons(ctx, time.Unix(30, 0).Add(defaultExp))
		xtest.FailOnErr(t, err)
		SoMsg("Deleted", deleted, ShouldEqual, 1)
	})
}

func testDeleteRevokedBeacons(t *testing.T, ctrl *gomock.Controller, db beacon.DBReadWrite) {
	ts := uint32(10)
	now := time.Unix(int64(ts)+2, 0)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	b3 := InsertBeacon(t, ctrl, db, Info3, 12, ts, beacon.UsageProp)
	b2 := InsertBeacon(t, ctrl, db, Info2, 13, ts, beacon.UsageProp)
	Convey("DeleteRevokedBeacons with no revocations should not delete anything", func() {
		deleted, err := db.DeleteRevokedBeacons(ctx, now)
		SoMsg("No err", err, ShouldBeNil)
		SoMsg("No deletions", deleted, ShouldBeZeroValue)
		results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, addr.IA{})
		xtest.FailOnErr(t, err)
		CheckResults(t, results, []beacon.Beacon{b2, b3})
	})
	srev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
		IfID:         Info3[2].Ingress,
		RawIsdas:     Info3[2].IA.IAInt(),
		LinkType:     proto.LinkType_child,
		RawTimestamp: ts,
		RawTTL:       10,
	}, infra.NullSigner)
	xtest.FailOnErr(t, err)
	InsertRevocation(t, db, srev1)
	Convey("DeleteRevokedBeacon with revocation on one beacon should delete it", func() {
		deleted, err := db.DeleteRevokedBeacons(ctx, now)
		SoMsg("No err", err, ShouldBeNil)
		SoMsg("1 deletions", deleted, ShouldEqual, 1)
		results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, addr.IA{})
		xtest.FailOnErr(t, err)
		CheckResults(t, results, []beacon.Beacon{b2})
	})
	srev2, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
		IfID:         Info2[1].Ingress,
		RawIsdas:     Info2[1].IA.IAInt(),
		LinkType:     proto.LinkType_child,
		RawTimestamp: ts,
		RawTTL:       10,
	}, infra.NullSigner)
	xtest.FailOnErr(t, err)
	InsertRevocation(t, db, srev2)
	Convey("DeleteRevokedBeacon with revocation on both beacons should delete both", func() {
		deleted, err := db.DeleteRevokedBeacons(ctx, now)
		SoMsg("No err", err, ShouldBeNil)
		SoMsg("2 deletions", deleted, ShouldEqual, 2)
		results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, addr.IA{})
		CheckEmpty(t, "deleted beacons", results, err)
	})
}

func testAllRevocations(t *testing.T, _ *gomock.Controller, db beacon.DBReadWrite) {
	Convey("AllRevocations works correctly", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		Convey("AllRevocations on empty db should return an empty channel", func() {
			revs, err := db.AllRevocations(ctx)
			CheckEmptyRevs(t, revs, err)
		})
		ts := util.TimeToSecs(time.Now().Add(-5 * time.Second))
		srev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
			IfID:         Info3[2].Ingress,
			RawIsdas:     Info3[2].IA.IAInt(),
			LinkType:     proto.LinkType_child,
			RawTimestamp: ts,
			RawTTL:       10,
		}, infra.NullSigner)
		xtest.FailOnErr(t, err)
		Convey("AllRevocations returns revocations in db", func() {
			InsertRevocation(t, db, srev1)
			revs, err := db.AllRevocations(ctx)
			SoMsg("Err", err, ShouldBeNil)
			CheckRevs(t, revs, []*path_mgmt.SignedRevInfo{srev1})
		})
	})
}

func testInsertUpdateRevocation(t *testing.T, _ *gomock.Controller, db beacon.DBReadWrite) {
	Convey("InsertRevocation updates existing rev", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		ts := util.TimeToSecs(time.Now().Add(-5 * time.Second))
		srev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
			IfID:         Info3[2].Ingress,
			RawIsdas:     Info3[2].IA.IAInt(),
			LinkType:     proto.LinkType_child,
			RawTimestamp: ts,
			RawTTL:       20,
		}, infra.NullSigner)
		xtest.FailOnErr(t, err)
		err = db.InsertRevocation(ctx, srev1)
		SoMsg("No err expected", err, ShouldBeNil)
		srev2, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
			IfID:         Info3[2].Ingress,
			RawIsdas:     Info3[2].IA.IAInt(),
			LinkType:     proto.LinkType_child,
			RawTimestamp: ts + 1,
			RawTTL:       10,
		}, infra.NullSigner)
		xtest.FailOnErr(t, err)
		err = db.InsertRevocation(ctx, srev2)
		SoMsg("No err expected", err, ShouldBeNil)
		revs, err := db.AllRevocations(ctx)
		SoMsg("Err", err, ShouldBeNil)
		CheckRevs(t, revs, []*path_mgmt.SignedRevInfo{srev2})
		Convey("Insert an older revocation keeps the newer one in the DB", func() {
			err = db.InsertRevocation(ctx, srev1)
			SoMsg("No err expected", err, ShouldBeNil)
			revs, err := db.AllRevocations(ctx)
			SoMsg("Err", err, ShouldBeNil)
			CheckRevs(t, revs, []*path_mgmt.SignedRevInfo{srev2})
		})
	})
}

func testReadWithRevocations(t *testing.T, ctrl *gomock.Controller, db beacon.DBReadWrite) {
	Convey("Beacons with revocations should not be returned", func() {
		ts := util.TimeToSecs(time.Now().Add(-5 * time.Second))
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		b3 := InsertBeacon(t, ctrl, db, Info3, 12, ts, beacon.UsageProp)
		b2 := InsertBeacon(t, ctrl, db, Info2, 13, ts, beacon.UsageProp)
		results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, addr.IA{})
		xtest.FailOnErr(t, err)
		CheckResults(t, results, []beacon.Beacon{b2, b3})
		Convey("Test revoking an interface that is on one beacon", func() {
			sRev, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
				IfID:         Info3[2].Ingress,
				RawIsdas:     Info3[2].IA.IAInt(),
				LinkType:     proto.LinkType_child,
				RawTimestamp: ts,
				RawTTL:       10,
			}, infra.NullSigner)
			xtest.FailOnErr(t, err)
			InsertRevocation(t, db, sRev)
			results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, addr.IA{})
			xtest.FailOnErr(t, err)
			CheckResults(t, results, []beacon.Beacon{b2})
		})
	})
}

func testDeleteRevocation(t *testing.T, _ *gomock.Controller, db beacon.DBReadWrite) {
	Convey("DeleteRevocations should delete revocations", func() {
		ts := util.TimeToSecs(time.Now().Add(-5 * time.Second))
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		Convey("DeleteRevocations on empty db should not do anything", func() {
			err := db.DeleteRevocation(ctx, Info3[2].IA, Info3[2].Ingress)
			SoMsg("No err expected", err, ShouldBeNil)
		})
		srev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
			IfID:         Info3[2].Ingress,
			RawIsdas:     Info3[2].IA.IAInt(),
			LinkType:     proto.LinkType_child,
			RawTimestamp: ts,
			RawTTL:       10,
		}, infra.NullSigner)
		xtest.FailOnErr(t, err)
		InsertRevocation(t, db, srev1)
		Convey("Deleting an existing revocation removes it", func() {
			err := db.DeleteRevocation(ctx, Info3[2].IA, Info3[2].Ingress)
			SoMsg("No err expected", err, ShouldBeNil)
			revs, err := db.AllRevocations(ctx)
			CheckEmptyRevs(t, revs, err)
		})
		Convey("Deleting non-existing other revocation does not delete existing", func() {
			err := db.DeleteRevocation(ctx, Info3[2].IA, Info3[2].Egress)
			SoMsg("No err expected", err, ShouldBeNil)
			revs, err := db.AllRevocations(ctx)
			SoMsg("Err", err, ShouldBeNil)
			CheckRevs(t, revs, []*path_mgmt.SignedRevInfo{srev1})
		})
	})
}

func testDeleteExpiredRevocations(t *testing.T, _ *gomock.Controller, db beacon.DBReadWrite) {
	Convey("DeleteExpiredRevocations should delete expired revocations", func() {
		now := time.Now()
		ts := util.TimeToSecs(now.Add(-5 * time.Second))
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		Convey("DeleteExpiredRevocation on empty DB should work", func() {
			cnt, err := db.DeleteExpiredRevocations(ctx, now)
			SoMsg("No err expected", err, ShouldBeNil)
			SoMsg("No deletion expected", cnt, ShouldBeZeroValue)
			revs, err := db.AllRevocations(ctx)
			CheckEmptyRevs(t, revs, err)
		})
		srev1, err := path_mgmt.NewSignedRevInfo(&path_mgmt.RevInfo{
			IfID:         Info3[2].Ingress,
			RawIsdas:     Info3[2].IA.IAInt(),
			LinkType:     proto.LinkType_child,
			RawTimestamp: ts,
			RawTTL:       10,
		}, infra.NullSigner)
		xtest.FailOnErr(t, err)
		InsertRevocation(t, db, srev1)
		Convey("DeleteExpiredRevocation should not delete non-expired revocation", func() {
			cnt, err := db.DeleteExpiredRevocations(ctx, now)
			SoMsg("No err expected", err, ShouldBeNil)
			SoMsg("No deletion expected", cnt, ShouldBeZeroValue)
			revs, err := db.AllRevocations(ctx)
			SoMsg("Err", err, ShouldBeNil)
			CheckRevs(t, revs, []*path_mgmt.SignedRevInfo{srev1})
		})
		Convey("DeleteExpiredRevocation should delete expired revocation", func() {
			cnt, err := db.DeleteExpiredRevocations(ctx, now.Add(6*time.Second))
			SoMsg("No err expected", err, ShouldBeNil)
			SoMsg("Deletion expected", cnt, ShouldEqual, 1)
			revs, err := db.AllRevocations(ctx)
			CheckEmptyRevs(t, revs, err)
		})
	})
}

func testRollback(t *testing.T, ctrl *gomock.Controller, db beacon.DB) {
	Convey("Test transaction rollback", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		tx, err := db.BeginTransaction(ctx, nil)
		SoMsg("Transaction begin should not fail", err, ShouldBeNil)
		b, _ := AllocBeacon(t, ctrl, Info3, 12, uint32(10))
		inserted, err := tx.InsertBeacon(ctx, b, beacon.UsageProp)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("Insert should succeed", inserted, ShouldEqual, 1)
		err = tx.Rollback()
		SoMsg("Rollback should not fail", err, ShouldBeNil)
		results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, addr.IA{})
		CheckEmpty(t, beacon.UsageProp.String(), results, err)
	})
}

func InsertBeacon(t *testing.T, ctrl *gomock.Controller, db beacon.DBReadWrite, ases []IfInfo,
	inIfId common.IFIDType, infoTS uint32, allowed beacon.Usage) beacon.Beacon {
	b, _ := AllocBeacon(t, ctrl, ases, inIfId, infoTS)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	_, err := db.InsertBeacon(ctx, b, allowed)
	xtest.FailOnErr(t, err)
	return b
}

func InsertRevocation(t *testing.T, db beacon.DBReadWrite, sRev *path_mgmt.SignedRevInfo) {
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	err := db.InsertRevocation(ctx, sRev)
	xtest.FailOnErr(t, err)
}

type PeerEntry struct {
	IA      addr.IA
	Ingress common.IFIDType
}

type IfInfo struct {
	IA      addr.IA
	Ingress common.IFIDType
	Egress  common.IFIDType
	Peers   []PeerEntry
}

func AllocBeacon(t *testing.T, ctrl *gomock.Controller, ases []IfInfo, inIfId common.IFIDType,
	infoTS uint32) (beacon.Beacon, common.RawBytes) {

	entries := make([]*seg.ASEntry, len(ases))
	for i, as := range ases {
		prev := addr.IA{}
		if i > 0 {
			prev = ases[i-1].IA
		}
		next := addr.IA{}
		if i < len(ases)-1 {
			next = ases[i+1].IA
		}
		hops := []*seg.HopEntry{
			allocHopEntry(prev, next, allocRawHop(as.Ingress, as.Egress)),
		}
		for _, peer := range as.Peers {
			hops = append(hops, allocHopEntry(peer.IA, next, allocRawHop(peer.Ingress, as.Egress)))
		}

		entries[i] = &seg.ASEntry{
			RawIA:      as.IA.IAInt(),
			HopEntries: hops,
		}
	}
	info := &spath.InfoField{
		TsInt: infoTS,
		ISD:   1,
		Hops:  uint8(len(ases)),
	}
	pseg, err := seg.NewSeg(info)
	xtest.FailOnErr(t, err)
	signer := mock_seg.NewMockSigner(ctrl)
	signer.EXPECT().Sign(gomock.AssignableToTypeOf(common.RawBytes{})).Return(
		&proto.SignS{}, nil).AnyTimes()
	for _, entry := range entries {
		err := pseg.AddASEntry(entry, signer)
		xtest.FailOnErr(t, err)
	}
	segID, err := pseg.ID()
	xtest.FailOnErr(t, err)
	_, err = pseg.FullId()
	xtest.FailOnErr(t, err)
	return beacon.Beacon{Segment: pseg, InIfId: inIfId}, segID
}

func allocRawHop(ingress, egress common.IFIDType) common.RawBytes {
	raw := make([]byte, 8)
	hf := spath.HopField{
		ConsIngress: ingress,
		ConsEgress:  egress,
		ExpTime:     spath.DefaultHopFExpiry,
	}
	hf.Write(raw)
	return raw
}

func allocHopEntry(inIA, outIA addr.IA, hopF common.RawBytes) *seg.HopEntry {
	return &seg.HopEntry{
		RawInIA:     inIA.IAInt(),
		RawOutIA:    outIA.IAInt(),
		RawHopField: hopF,
	}
}
