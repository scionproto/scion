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

package pathdbtest

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

var (
	ia330 = addr.IA{I: 1, A: 0xff0000000330}
	ia311 = addr.IA{I: 1, A: 0xff0000000311}
	ia331 = addr.IA{I: 1, A: 0xff0000000331}
	ia332 = addr.IA{I: 1, A: 0xff0000000332}

	ifs1 = []uint64{0, 5, 2, 3, 6, 3, 1, 0}
	ifs2 = []uint64{0, 4, 2, 3, 1, 3, 2, 0}

	hpCfgIDs = []*query.HPCfgID{
		&query.NullHpCfgID,
		{ia330, 0xdeadbeef},
	}
	segType = proto.PathSegType_up

	ifspecs = []query.IntfSpec{
		{IA: ia330, IfID: 5},
		{IA: ia331, IfID: 2},
		{IA: ia331, IfID: 3},
		{IA: ia331, IfID: 6},
		{IA: ia332, IfID: 1},
	}
	timeout = time.Second
)

// TestPathDB should be used to test any implementation of the PathDB interface.
// An implementation of the PathDB interface should at least have one test method that calls
// this test-suite. The calling test code should have a top level Convey block.
//
// setup should return a PathDB in a clean state, i.e. no entries in the DB.
// cleanup can be used to release any resources that have been allocated during setup.
func TestPathDB(t *testing.T, setup func() pathdb.PathDB, cleanup func()) {
	testWrapper := func(test func(*testing.T, pathdb.PathDB)) func() {
		return func() {
			test(t, setup())
			cleanup()
		}
	}

	Convey("Delete", func() { testDelete(t, setup, cleanup) })
	Convey("InsertWithHpCfgIDsFull", testWrapper(testInsertWithHpCfgIDsFull))
	Convey("UpdateExisting", testWrapper(testUpdateExisting))
	Convey("UpdateOlderIgnored", testWrapper(testUpdateOlderIgnored))
	Convey("UpdateIntfToSeg", testWrapper(testUpdateIntfToSeg))
	Convey("DeleteExpired", testWrapper(testDeleteExpired))
	Convey("GetMixed", testWrapper(testGetMixed))
	Convey("GetAll", testWrapper(testGetAll))
	Convey("GetStartsAtEndsAt", testWrapper(testGetStartsAtEndsAt))
	Convey("GetWithIntfs", testWrapper(testGetWithIntfs))
	Convey("GetWithHpCfgIDs", testWrapper(testGetWithHpCfgIDs))
	Convey("ModifiedIDs", testWrapper(testGetModifiedIDs))
	Convey("NextQuery", testWrapper(testNextQuery))
}

func testDelete(t *testing.T, setup func() pathdb.PathDB, cleanup func()) {
	testCases := []struct {
		Name        string
		Setup       func(ctx context.Context, t *testing.T, pathDB pathdb.PathDB) *query.Params
		DeleteCount int
	}{
		{
			Name: "Delete by id",
			Setup: func(ctx context.Context, t *testing.T, pathDB pathdb.PathDB) *query.Params {
				TS := uint32(10)
				pseg, segID := AllocPathSegment(t, ifs1, TS)
				InsertSeg(t, ctx, pathDB, pseg, hpCfgIDs)
				return &query.Params{SegIDs: []common.RawBytes{segID}}
			},
			DeleteCount: 1,
		},
		{
			Name: "Delete by interfaces",
			Setup: func(ctx context.Context, t *testing.T, pathDB pathdb.PathDB) *query.Params {
				TS := uint32(10)
				pseg, _ := AllocPathSegment(t, ifs1, TS)
				InsertSeg(t, ctx, pathDB, pseg, hpCfgIDs)
				pseg, _ = AllocPathSegment(t, ifs2, TS)
				InsertSeg(t, ctx, pathDB, pseg, hpCfgIDs)
				return &query.Params{
					Intfs: []*query.IntfSpec{&ifspecs[0]},
				}
			},
			DeleteCount: 1,
		},
	}
	Convey("Delete should correctly remove a path segment", func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				pathDB := setup()
				defer cleanup()
				ctx, cancelF := context.WithTimeout(context.Background(), timeout)
				defer cancelF()

				params := tc.Setup(ctx, t, pathDB)
				// Call
				deleted, err := pathDB.Delete(ctx, params)
				xtest.FailOnErr(t, err)
				// Check return value.
				SoMsg("Deleted", deleted, ShouldEqual, tc.DeleteCount)
			})
		}
	})
}

func testInsertWithHpCfgIDsFull(t *testing.T, pathDB pathdb.PathDB) {
	Convey("InsertWithHpCfgID should correctly insert a new segment", func() {
		TS := uint32(10)
		pseg, segID := AllocPathSegment(t, ifs1, TS)

		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		// Call
		inserted, err := pathDB.InsertWithHPCfgIDs(ctx, seg.NewMeta(pseg, segType), hpCfgIDs)
		xtest.FailOnErr(t, err)
		// Check return value.
		SoMsg("Inserted", inserted, ShouldEqual, 1)
		// Check Insert.
		res, err := pathDB.Get(ctx, &query.Params{SegIDs: []common.RawBytes{segID}})
		xtest.FailOnErr(t, err)
		checkResult(t, res, pseg, hpCfgIDs)
	})
}

func testUpdateExisting(t *testing.T, pathDB pathdb.PathDB) {
	Convey("InsertWithHpCfgID should correctly update a new segment", func() {
		oldTS := uint32(10)
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		oldSeg, segID := AllocPathSegment(t, ifs1, oldTS)
		newTS := uint32(20)
		newSeg, newSegID := AllocPathSegment(t, ifs1, newTS)
		SoMsg("IDs should match", newSegID, ShouldResemble, segID)
		InsertSeg(t, ctx, pathDB, oldSeg, hpCfgIDs[:1])
		// Call
		inserted := InsertSeg(t, ctx, pathDB, newSeg, hpCfgIDs)
		// Check return value.
		SoMsg("Inserted", inserted, ShouldEqual, 1)
		// Check Insert
		res, err := pathDB.Get(ctx, &query.Params{SegIDs: []common.RawBytes{segID}})
		xtest.FailOnErr(t, err)
		checkResult(t, res, newSeg, hpCfgIDs)
	})
}

func testUpdateOlderIgnored(t *testing.T, pathDB pathdb.PathDB) {
	Convey("InsertWithHpCfgID should correctly ignore an older segment", func() {
		newTS := uint32(20)
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		newSeg, newSegID := AllocPathSegment(t, ifs1, newTS)
		oldTS := uint32(10)
		oldSeg, oldSegId := AllocPathSegment(t, ifs1, oldTS)
		SoMsg("IDs should match", oldSegId, ShouldResemble, newSegID)
		InsertSeg(t, ctx, pathDB, newSeg, hpCfgIDs)
		// Call
		inserted := InsertSeg(t, ctx, pathDB, oldSeg, hpCfgIDs[:1])
		// Check return value.
		SoMsg("Inserted", inserted, ShouldEqual, 0)
		// Check Insert
		res, err := pathDB.Get(ctx, &query.Params{SegIDs: []common.RawBytes{newSegID}})
		xtest.FailOnErr(t, err)
		checkResult(t, res, newSeg, hpCfgIDs)
	})
}

func testUpdateIntfToSeg(t *testing.T, pathDB pathdb.PathDB) {
	Convey("Updating a segment with new peer links should update interface to seg mapping", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		ps, _ := AllocPathSegment(t, ifs1, uint32(20))
		InsertSeg(t, ctx, pathDB, ps, hpCfgIDs)
		checkInterfacesPresent(t, ctx, ps.ASEntries, pathDB)
		// Create a new segment with an additional peer entry.
		info := &spath.InfoField{
			TsInt: uint32(30),
			ISD:   1,
			Hops:  3,
		}
		newPs, err := seg.NewSeg(info)
		xtest.FailOnErr(t, err)
		hfr := make([]byte, 8)
		hf := spath.HopField{
			ConsIngress: common.IFIDType(common.IFIDType(23)),
			ExpTime:     spath.DefaultHopFExpiry,
		}
		hf.Write(hfr)
		he := allocHopEntry(ia331, ia332, hfr)
		asEntries := ps.ASEntries
		asEntries[1].HopEntries = append(asEntries[1].HopEntries, he)
		for _, asEntry := range asEntries {
			err = newPs.AddASEntry(asEntry, proto.SignType_none, nil)
			xtest.FailOnErr(t, err)
		}
		InsertSeg(t, ctx, pathDB, newPs, hpCfgIDs)
		checkInterfacesPresent(t, ctx, newPs.ASEntries, pathDB)
		// Now check that the new interface is removed again.
		ps, _ = AllocPathSegment(t, ifs1, uint32(40))
		InsertSeg(t, ctx, pathDB, ps, hpCfgIDs)
		checkInterfacesPresent(t, ctx, ps.ASEntries, pathDB)
		checkInterface(t, ctx, newPs.ASEntries[1].IA(), hf.ConsIngress, pathDB, false)
	})
}

func testDeleteExpired(t *testing.T, pathDB pathdb.PathDB) {
	Convey("DeleteExpired should delete expired segments", func() {
		ts1 := uint32(10)
		ts2 := uint32(20)
		// defaultExp is the default expiry of the hopfields.
		defaultExp := spath.DefaultHopFExpiry.ToDuration()
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		pseg1, _ := AllocPathSegment(t, ifs1, ts1)
		pseg2, _ := AllocPathSegment(t, ifs2, ts2)
		InsertSeg(t, ctx, pathDB, pseg1, hpCfgIDs)
		InsertSeg(t, ctx, pathDB, pseg2, hpCfgIDs)
		deleted, err := pathDB.DeleteExpired(ctx, time.Unix(10, 0).Add(defaultExp))
		xtest.FailOnErr(t, err)
		SoMsg("Deleted", deleted, ShouldEqual, 0)
		deleted, err = pathDB.DeleteExpired(ctx, time.Unix(20, 0).Add(defaultExp))
		xtest.FailOnErr(t, err)
		SoMsg("Deleted", deleted, ShouldEqual, 1)
		deleted, err = pathDB.DeleteExpired(ctx, time.Unix(30, 0).Add(defaultExp))
		xtest.FailOnErr(t, err)
		SoMsg("Deleted", deleted, ShouldEqual, 1)
	})
}

func testGetMixed(t *testing.T, pathDB pathdb.PathDB) {
	Convey("Get should return the correct path segments", func() {
		// Setup
		TS := uint32(10)
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		pseg1, segID1 := AllocPathSegment(t, ifs1, TS)
		pseg2, _ := AllocPathSegment(t, ifs2, TS)
		InsertSeg(t, ctx, pathDB, pseg1, hpCfgIDs)
		InsertSeg(t, ctx, pathDB, pseg2, hpCfgIDs[:1])
		params := &query.Params{
			SegIDs:   []common.RawBytes{segID1},
			SegTypes: []proto.PathSegType{proto.PathSegType_up},
		}
		// Call
		res, err := pathDB.Get(ctx, params)
		xtest.FailOnErr(t, err)
		resSegID, _ := res[0].Seg.ID()
		SoMsg("Result count", len(res), ShouldEqual, 1)
		SoMsg("SegIDs match", resSegID, ShouldResemble, segID1)
		checkSameHpCfgs("HpCfgIDs match", res[0].HpCfgIDs, hpCfgIDs)
	})
}

func testGetAll(t *testing.T, pathDB pathdb.PathDB) {
	Convey("Get should return the all path segments", func() {
		// Setup
		TS := uint32(10)
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		pseg1, segID1 := AllocPathSegment(t, ifs1, TS)
		pseg2, segID2 := AllocPathSegment(t, ifs2, TS)
		InsertSeg(t, ctx, pathDB, pseg1, hpCfgIDs)
		InsertSeg(t, ctx, pathDB, pseg2, hpCfgIDs[:1])
		// Call
		res, err := pathDB.Get(ctx, nil)
		xtest.FailOnErr(t, err)
		SoMsg("Result count", len(res), ShouldEqual, 2)
		for _, r := range res {
			resSegID, _ := r.Seg.ID()
			if bytes.Compare(resSegID, segID1) == 0 {
				checkSameHpCfgs("HpCfgIDs match", r.HpCfgIDs, hpCfgIDs)
			} else if bytes.Compare(resSegID, segID2) == 0 {
				checkSameHpCfgs("HpCfgIDs match", r.HpCfgIDs, hpCfgIDs[:1])
			} else {
				t.Fatal("Unexpected result", "seg", r.Seg)
			}
		}
	})
}

func testGetStartsAtEndsAt(t *testing.T, pathDB pathdb.PathDB) {
	Convey("Get should return all path segments starting or ending at", func() {
		// Setup
		TS := uint32(10)
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		pseg1, _ := AllocPathSegment(t, ifs1, TS)
		pseg2, _ := AllocPathSegment(t, ifs2, TS)
		InsertSeg(t, ctx, pathDB, pseg1, hpCfgIDs)
		InsertSeg(t, ctx, pathDB, pseg2, hpCfgIDs[:1])
		// Call
		res, err := pathDB.Get(ctx, &query.Params{StartsAt: []addr.IA{ia330, ia332}})
		xtest.FailOnErr(t, err)
		SoMsg("Result count", len(res), ShouldEqual, 2)
		res, err = pathDB.Get(ctx, &query.Params{EndsAt: []addr.IA{ia330, ia332}})
		xtest.FailOnErr(t, err)
		SoMsg("Result count", len(res), ShouldEqual, 2)
	})
}

func testGetWithIntfs(t *testing.T, pathDB pathdb.PathDB) {
	Convey("Get should return all path segment with given ifIDs", func() {
		// Setup
		TS := uint32(10)
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		pseg1, _ := AllocPathSegment(t, ifs1, TS)
		pseg2, _ := AllocPathSegment(t, ifs2, TS)
		InsertSeg(t, ctx, pathDB, pseg1, hpCfgIDs)
		InsertSeg(t, ctx, pathDB, pseg2, hpCfgIDs[:1])
		params := &query.Params{
			Intfs: []*query.IntfSpec{
				{ia330, 5},
				{ia332, 2},
			},
		}
		// Call
		res, err := pathDB.Get(ctx, params)
		xtest.FailOnErr(t, err)
		SoMsg("Result count", len(res), ShouldEqual, 2)
	})
}

func testGetWithHpCfgIDs(t *testing.T, pathDB pathdb.PathDB) {
	Convey("Get should return all path segment with given HpCfgIDs", func() {
		// Setup
		TS := uint32(10)
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		pseg1, _ := AllocPathSegment(t, ifs1, TS)
		pseg2, _ := AllocPathSegment(t, ifs2, TS)
		InsertSeg(t, ctx, pathDB, pseg1, hpCfgIDs)
		InsertSeg(t, ctx, pathDB, pseg2, hpCfgIDs[:1])
		params := &query.Params{
			HpCfgIDs: hpCfgIDs[1:],
		}
		// Call
		res, err := pathDB.Get(ctx, params)
		xtest.FailOnErr(t, err)
		SoMsg("Result count", len(res), ShouldEqual, 1)
	})
}

func testGetModifiedIDs(t *testing.T, pathDB pathdb.PathDB) {
	Convey("Get with MinLastUpdate should return only segs that have been modified", func() {
		// Setup
		TS := uint32(10)
		now := time.Now()
		tAfter := now.Add(time.Second)
		ctx, cancelF := context.WithTimeout(context.Background(), timeout)
		defer cancelF()
		pseg1, _ := AllocPathSegment(t, ifs1, TS)
		pseg2, _ := AllocPathSegment(t, ifs2, TS)
		InsertSeg(t, ctx, pathDB, pseg1, hpCfgIDs)
		InsertSeg(t, ctx, pathDB, pseg2, hpCfgIDs[:1])
		q := &query.Params{
			MinLastUpdate: &tAfter,
		}
		res, err := pathDB.Get(ctx, q)
		xtest.FailOnErr(t, err)
		SoMsg("Result count", len(res), ShouldEqual, 0)
		tBefore := now.Add(-5 * time.Second)
		q = &query.Params{
			MinLastUpdate: &tBefore,
		}
		res, err = pathDB.Get(ctx, q)
		xtest.FailOnErr(t, err)
		SoMsg("Result count", len(res), ShouldEqual, 2)
		expectID1, err := pseg1.ID()
		xtest.FailOnErr(t, err)
		id1, err := res[0].Seg.ID()
		xtest.FailOnErr(t, err)
		SoMsg("ID 1", expectID1, ShouldResemble, id1)
		expectedID2, err := pseg2.ID()
		xtest.FailOnErr(t, err)
		id2, err := res[1].Seg.ID()
		SoMsg("ID 2", expectedID2, ShouldResemble, id2)
	})
}

func testNextQuery(t *testing.T, pathDB pathdb.PathDB) {
	Convey("NextQuery insert should always result in the latest timestamp", func() {
		ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
		defer cancelF()
		dst := xtest.MustParseIA("1-ff00:0:133")
		oldT := time.Now().Add(-10 * time.Second)
		updated, err := pathDB.InsertNextQuery(ctx, dst, oldT)
		xtest.FailOnErr(t, err)
		SoMsg("Should Insert new", updated, ShouldBeTrue)
		dbT, err := pathDB.GetNextQuery(ctx, dst)
		xtest.FailOnErr(t, err)
		SoMsg("Should return inserted time", dbT.Unix(), ShouldEqual, oldT.Unix())
		newT := time.Now()
		updated, err = pathDB.InsertNextQuery(ctx, dst, newT)
		xtest.FailOnErr(t, err)
		SoMsg("Should Update existing", updated, ShouldBeTrue)
		dbT, err = pathDB.GetNextQuery(ctx, dst)
		xtest.FailOnErr(t, err)
		SoMsg("Should return updated time", dbT.Unix(), ShouldEqual, newT.Unix())
		updated, err = pathDB.InsertNextQuery(ctx, dst, oldT)
		xtest.FailOnErr(t, err)
		SoMsg("Should not update to older", updated, ShouldBeFalse)
		dbT, err = pathDB.GetNextQuery(ctx, dst)
		xtest.FailOnErr(t, err)
		SoMsg("Should return updated time", dbT.Unix(), ShouldEqual, newT.Unix())
		dbT, err = pathDB.GetNextQuery(ctx, xtest.MustParseIA("1-ff00:0:122"))
		SoMsg("Should be nil", dbT, ShouldBeNil)
		ctx, cancelF = context.WithDeadline(context.Background(), time.Now().Add(-3*time.Second))
		defer cancelF()
		_, err = pathDB.GetNextQuery(ctx, xtest.MustParseIA("1-ff00:0:122"))
		SoMsg("Should error", err, ShouldNotBeNil)
	})
}

func AllocPathSegment(t *testing.T, ifs []uint64,
	expiration uint32) (*seg.PathSegment, common.RawBytes) {

	rawHops := make([][]byte, len(ifs)/2)
	for i := 0; i < len(ifs)/2; i++ {
		rawHops[i] = make([]byte, 8)
		hf := spath.HopField{
			ConsIngress: common.IFIDType(ifs[2*i]),
			ConsEgress:  common.IFIDType(ifs[2*i+1]),
			ExpTime:     spath.DefaultHopFExpiry,
		}
		hf.Write(rawHops[i])
	}
	ases := []*seg.ASEntry{
		{
			RawIA: ia330.IAInt(),
			HopEntries: []*seg.HopEntry{
				allocHopEntry(addr.IA{}, ia331, rawHops[0]),
			},
		},
		{
			RawIA: ia331.IAInt(),
			HopEntries: []*seg.HopEntry{
				allocHopEntry(ia330, ia332, rawHops[1]),
				allocHopEntry(ia311, ia332, rawHops[2]),
			},
		},
		{
			RawIA: ia332.IAInt(),
			HopEntries: []*seg.HopEntry{
				allocHopEntry(ia331, addr.IA{}, rawHops[3]),
			},
		},
	}
	info := &spath.InfoField{
		TsInt: expiration,
		ISD:   1,
		Hops:  3,
	}
	pseg, err := seg.NewSeg(info)
	xtest.FailOnErr(t, err)
	for _, ase := range ases {
		err := pseg.AddASEntry(ase, proto.SignType_none, nil)
		xtest.FailOnErr(t, err)
	}
	segID, err := pseg.ID()
	xtest.FailOnErr(t, err)
	_, err = pseg.FullId()
	xtest.FailOnErr(t, err)
	return pseg, segID
}

func allocHopEntry(inIA, outIA addr.IA, hopF common.RawBytes) *seg.HopEntry {
	return &seg.HopEntry{
		RawInIA:     inIA.IAInt(),
		RawOutIA:    outIA.IAInt(),
		RawHopField: hopF,
	}
}

func InsertSeg(t *testing.T, ctx context.Context, pathDB pathdb.PathDB,
	pseg *seg.PathSegment, hpCfgIDs []*query.HPCfgID) int {

	inserted, err := pathDB.InsertWithHPCfgIDs(ctx, seg.NewMeta(pseg, segType), hpCfgIDs)
	xtest.FailOnErr(t, err)
	return inserted
}

func checkResult(t *testing.T, results []*query.Result, expectedSeg *seg.PathSegment,
	hpCfgsIds []*query.HPCfgID) {

	SoMsg("Expect one result", len(results), ShouldEqual, 1)
	// Make sure the segment is properly initialized.
	_, err := results[0].Seg.ID()
	xtest.FailOnErr(t, err)
	_, err = results[0].Seg.FullId()
	xtest.FailOnErr(t, err)
	SoMsg("Segment should match", results[0].Seg, ShouldResemble, expectedSeg)
	checkSameHpCfgs("HiddenPath Ids should match", results[0].HpCfgIDs, hpCfgsIds)
}

func checkSameHpCfgs(msg string, actual, expected []*query.HPCfgID) {
	sort.Slice(actual, func(i, j int) bool {
		return actual[i].IA.I < actual[j].IA.I ||
			actual[i].IA.I == actual[j].IA.I && actual[i].IA.A < actual[j].IA.A ||
			actual[i].IA.Eq(actual[j].IA) && actual[i].ID < actual[j].ID
	})
	SoMsg(msg, actual, ShouldResemble, expected)
}

func checkInterfacesPresent(t *testing.T, ctx context.Context,
	expectedHopEntries []*seg.ASEntry, pathDB pathdb.PathDB) {

	for _, asEntry := range expectedHopEntries {
		for _, hopEntry := range asEntry.HopEntries {
			hof, err := hopEntry.HopField()
			xtest.FailOnErr(t, err)
			if hof.ConsIngress != 0 {
				checkInterface(t, ctx, asEntry.IA(), hof.ConsIngress, pathDB, true)
			}
			if hof.ConsEgress != 0 {
				checkInterface(t, ctx, asEntry.IA(), hof.ConsEgress, pathDB, true)
			}
		}
	}
}

func checkInterface(t *testing.T, ctx context.Context, ia addr.IA, ifId common.IFIDType,
	pathDB pathdb.PathDB, present bool) {

	r, err := pathDB.Get(ctx, &query.Params{
		Intfs: []*query.IntfSpec{
			{
				IA:   ia,
				IfID: ifId,
			},
		},
	})
	xtest.FailOnErr(t, err)
	if present {
		SoMsg(fmt.Sprintf("Interface should be present: %v#%d", ia, ifId), len(r), ShouldEqual, 1)
	} else {
		SoMsg(fmt.Sprintf("Interface should not be present: %v#%d", ia, ifId),
			len(r), ShouldBeZeroValue)
	}
}
