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
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/spath"
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
	testWrapper := func(test func(*testing.T, beacon.DBReadWrite)) func() {
		return func() {
			prepareCtx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, prepareCtx)
			test(t, db)
		}
	}
	Convey("InsertBeacon", testWrapper(testInsertBeacon))
	Convey("UpdateBeacon", testWrapper(testUpdateExisting))
	Convey("IgnoreBeaconUpdate", testWrapper(testUpdateOlderIgnored))
	Convey("CandidateBeacons", testWrapper(testCandidateBeacons))
	Convey("DeleteExpiredBeacons", testWrapper(testDeleteExpiredBeacons))
	txTestWrapper := func(test func(*testing.T, beacon.DBReadWrite)) func() {
		return func() {
			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, ctx)
			tx, err := db.BeginTransaction(ctx, nil)
			xtest.FailOnErr(t, err)
			test(t, tx)
			err = tx.Commit()
			xtest.FailOnErr(t, err)
		}
	}
	Convey("WithTransaction", func() {
		Convey("InsertBeacon", txTestWrapper(testInsertBeacon))
		Convey("UpdateBeacon", testWrapper(testUpdateExisting))
		Convey("IgnoreBeaconUpdate", testWrapper(testUpdateOlderIgnored))
		Convey("CandidateBeacons", txTestWrapper(testCandidateBeacons))
		Convey("DeleteExpiredBeacons", txTestWrapper(testDeleteExpiredBeacons))
		Convey("TestTransactionRollback", func() {
			prepareCtx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, prepareCtx)
			testRollback(t, db)
		})
	})
}

func testInsertBeacon(t *testing.T, db beacon.DBReadWrite) {
	Convey("InsertBeacon should correctly insert a new beacon", func() {
		TS := uint32(10)
		b, _ := AllocBeacon(t, Info3, 12, TS)

		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		inserted, err := db.InsertBeacon(ctx, b, beacon.UsageProp)
		SoMsg("Insert err", err, ShouldBeNil)
		SoMsg("Inserted", inserted, ShouldEqual, 1)
		// Fetch the candidate beacons
		results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp)
		SoMsg("CandidateBeacons err", err, ShouldBeNil)
		// There should only be one candidate beacon, and it should match the inserted.
		CheckResult(t, results, b)
		for _, usage := range []beacon.Usage{beacon.UsageUpReg, beacon.UsageDownReg,
			beacon.UsageCoreReg} {
			results, err = db.CandidateBeacons(ctx, 10, usage)
			CheckEmpty(t, usage.String(), results, err)
		}
	})
}

func testUpdateExisting(t *testing.T, db beacon.DBReadWrite) {
	Convey("InsertBeacon should correctly update a new beacon", func() {
		oldTS := uint32(10)
		oldB, oldId := AllocBeacon(t, Info3, 12, oldTS)

		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		inserted, err := db.InsertBeacon(ctx, oldB, beacon.UsageProp)
		SoMsg("Insert old err", err, ShouldBeNil)
		SoMsg("Inserted old", inserted, ShouldEqual, 1)
		newTS := uint32(20)
		newB, newId := AllocBeacon(t, Info3, 12, newTS)
		SoMsg("IDs should match", newId, ShouldResemble, oldId)
		inserted, err = db.InsertBeacon(ctx, newB, beacon.UsageDownReg)
		SoMsg("Insert new err", err, ShouldBeNil)
		SoMsg("Inserted new", inserted, ShouldEqual, 1)
		// Fetch the candidate beacons
		results, err := db.CandidateBeacons(ctx, 10, beacon.UsageDownReg)
		SoMsg("CandidateBeacons err", err, ShouldBeNil)
		// There should only be one candidate beacon, and it should match the inserted.
		CheckResult(t, results, newB)
		for _, usage := range []beacon.Usage{beacon.UsageUpReg, beacon.UsageProp,
			beacon.UsageCoreReg} {
			results, err = db.CandidateBeacons(ctx, 10, usage)
			CheckEmpty(t, usage.String(), results, err)
		}
	})
}

func testUpdateOlderIgnored(t *testing.T, db beacon.DBReadWrite) {
	Convey("InsertBeacon should correctly ignore an older beacon", func() {
		newTS := uint32(20)
		newB, newId := AllocBeacon(t, Info3, 12, newTS)

		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		inserted, err := db.InsertBeacon(ctx, newB, beacon.UsageProp)
		SoMsg("Insert new err", err, ShouldBeNil)
		SoMsg("Inserted new", inserted, ShouldEqual, 1)
		oldTS := uint32(10)
		oldB, oldId := AllocBeacon(t, Info3, 12, oldTS)
		SoMsg("IDs should match", newId, ShouldResemble, oldId)
		inserted, err = db.InsertBeacon(ctx, oldB, beacon.UsageDownReg)
		SoMsg("Insert old err", err, ShouldBeNil)
		SoMsg("Inserted old", inserted, ShouldEqual, 0)
		// Fetch the candidate beacons
		results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp)
		SoMsg("CandidateBeacons err", err, ShouldBeNil)
		// There should only be one candidate beacon, and it should match the inserted.
		CheckResult(t, results, newB)
		for _, usage := range []beacon.Usage{beacon.UsageUpReg, beacon.UsageDownReg,
			beacon.UsageCoreReg} {
			results, err = db.CandidateBeacons(ctx, 10, usage)
			CheckEmpty(t, usage.String(), results, err)
		}
	})
}

// CheckResult checks that the expected beacon is returned in results, and
// that it is the only returned beacon
func CheckResult(t *testing.T, results <-chan beacon.BeaconOrErr, expected beacon.Beacon) {
	beacons := make([]beacon.BeaconOrErr, 0, 1)
	for b := range results {
		beacons = append(beacons, b)
	}
	SoMsg("Expect one result", len(beacons), ShouldEqual, 1)
	SoMsg("Contains beacon", beacons[0].Err, ShouldBeNil)
	// Make sure the segment is properly initialized.
	_, err := beacons[0].Beacon.Segment.ID()
	xtest.FailOnErr(t, err)
	_, err = beacons[0].Beacon.Segment.FullId()
	xtest.FailOnErr(t, err)
	SoMsg("Beacon.Segment should match", beacons[0].Beacon.Segment, ShouldResemble,
		expected.Segment)
	SoMsg("Beacon.InIfId should match", beacons[0].Beacon.InIfId, ShouldEqual, expected.InIfId)
}

// CheckEmpty checks that no beacon is in the result channel.
func CheckEmpty(t *testing.T, name string, results <-chan beacon.BeaconOrErr, err error) {
	SoMsg(name+" err", err, ShouldBeNil)
	for res := range results {
		// If we end up in this execution tree, the test failed.
		SoMsg("Found beacon "+name, res, ShouldBeFalse)
	}
}

func testCandidateBeacons(t *testing.T, db beacon.DBReadWrite) {
	Convey("InsertBeacon should correctly ignore an older beacon", func() {
		// Insert beacons from longest to shortest path such that the insertion
		// order is not sorted the same as the expected outcome.
		var beacons []beacon.Beacon
		for i, info := range [][]IfInfo{Info3, Info2, Info1} {
			b := InsertBeacon(t, db, info, 12, uint32(i), beacon.UsageProp)
			// Prepend to get beacons sorted from shortest to longest path.
			beacons = append([]beacon.Beacon{b}, beacons...)
		}
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp)
		SoMsg("Err", err, ShouldBeNil)
		for i, expected := range beacons {
			select {
			case res := <-results:
				SoMsg(fmt.Sprintf("Beacon %d err", i), res.Err, ShouldBeNil)
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
	})
}

func testDeleteExpiredBeacons(t *testing.T, db beacon.DBReadWrite) {
	Convey("DeleteExpired should delete expired segments", func() {
		ts1 := uint32(10)
		ts2 := uint32(20)
		// defaultExp is the default expiry of the hopfields.
		defaultExp := spath.DefaultHopFExpiry.ToDuration()
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		InsertBeacon(t, db, Info3, 12, ts1, beacon.UsageProp)
		InsertBeacon(t, db, Info2, 13, ts2, beacon.UsageProp)
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

func testRollback(t *testing.T, db beacon.DB) {
	Convey("Test transaction rollback", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		tx, err := db.BeginTransaction(ctx, nil)
		SoMsg("Transaction begin should not fail", err, ShouldBeNil)
		b, _ := AllocBeacon(t, Info3, 12, uint32(10))
		inserted, err := tx.InsertBeacon(ctx, b, beacon.UsageProp)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("Insert should succeed", inserted, ShouldEqual, 1)
		err = tx.Rollback()
		SoMsg("Rollback should not fail", err, ShouldBeNil)
		results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp)
		CheckEmpty(t, beacon.UsageProp.String(), results, err)
	})
}

func InsertBeacon(t *testing.T, db beacon.DBReadWrite, ases []IfInfo, inIfId common.IFIDType,
	infoTS uint32, allowed beacon.Usage) beacon.Beacon {
	b, _ := AllocBeacon(t, ases, inIfId, infoTS)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	_, err := db.InsertBeacon(ctx, b, allowed)
	xtest.FailOnErr(t, err)
	return b
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

func AllocBeacon(t *testing.T, ases []IfInfo, inIfId common.IFIDType,
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
	for _, entry := range entries {
		err := pseg.AddASEntry(entry, proto.SignType_none, nil)
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
