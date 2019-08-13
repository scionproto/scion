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

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/ctrl/seg/mock_seg"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/pathpol"
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
		{IA: ia330, ID: 0xdeadbeef},
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

// TestablePathDB extends the path db interface with methods that are needed for testing.
type TestablePathDB interface {
	pathdb.PathDB
	// Prepare should reset the internal state so that the DB is empty and is ready to be tested.
	Prepare(t *testing.T, ctx context.Context)
}

// TestPathDB should be used to test any implementation of the PathDB interface.
// An implementation of the PathDB interface should at least have one test method that calls
// this test-suite. The calling test code should have a top level Convey block.
//
// setup should return a PathDB in a clean state, i.e. no entries in the DB.
// cleanup can be used to release any resources that have been allocated during setup.
func TestPathDB(t *testing.T, db TestablePathDB) {
	testWrapper := func(test func(*testing.T, *gomock.Controller,
		pathdb.ReadWrite)) func(t *testing.T) {

		return func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			prepareCtx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, prepareCtx)
			test(t, ctrl, db)
		}
	}
	tableWrapper := func(inTx bool, test func(t *testing.T, db TestablePathDB,
		inTx bool)) func(t *testing.T) {

		return func(t *testing.T) {
			test(t, db, inTx)
		}
	}
	t.Run("Delete",
		tableWrapper(false, testDelete))
	t.Run("InsertWithHpCfgID should correctly insert a new segment",
		testWrapper(testInsertWithHpCfgIDsFull))
	t.Run("InsertWithHpCfgID should correctly update a new segment",
		testWrapper(testUpdateExisting))
	t.Run("InsertWithHpCfgID should correctly ignore an older segment",
		testWrapper(testUpdateOlderIgnored))
	t.Run("Updating a segment with new peer links should update interface to seg mapping",
		testWrapper(testUpdateIntfToSeg))
	t.Run("DeleteExpired should delete expired segments",
		testWrapper(testDeleteExpired))
	t.Run("Get should return the correct path segments",
		testWrapper(testGetMixed))
	t.Run("Get with nil params should return all path segments",
		testWrapper(testGetNilParams))
	t.Run("GetAll",
		testWrapper(testGetAll))
	t.Run("Get should return all path segments starting or ending at",
		testWrapper(testGetStartsAtEndsAt))
	t.Run("Get should return all path segment with given ifIDs",
		testWrapper(testGetWithIntfs))
	t.Run("Get should return all path segment with given HpCfgIDs",
		testWrapper(testGetWithHpCfgIDs))
	t.Run("Get with MinLastUpdate should return only segs that have been modified",
		testWrapper(testGetModifiedIDs))
	t.Run("NextQuery",
		testWrapper(testNextQuery))
	t.Run("DeleteExpiredNQ",
		tableWrapper(false, testNextQueryDeleteExpired))
	t.Run("DeleteNQ",
		tableWrapper(false, testDeleteNQ))

	txTestWrapper := func(test func(*testing.T, *gomock.Controller,
		pathdb.ReadWrite)) func(t *testing.T) {

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
		t.Run("Delete",
			tableWrapper(true, testDelete))
		t.Run("InsertWithHpCfgID should correctly insert a new segment",
			txTestWrapper(testInsertWithHpCfgIDsFull))
		t.Run("InsertWithHpCfgID should correctly update a new segment",
			txTestWrapper(testUpdateExisting))
		t.Run("InsertWithHpCfgID should correctly ignore an older segment",
			txTestWrapper(testUpdateOlderIgnored))
		t.Run("Updating a segment with new peer links should update interface to seg mapping",
			txTestWrapper(testUpdateIntfToSeg))
		t.Run("DeleteExpired should delete expired segments",
			txTestWrapper(testDeleteExpired))
		t.Run("Get should return the correct path segments",
			txTestWrapper(testGetMixed))
		t.Run("Get with nil params should return all path segments",
			txTestWrapper(testGetNilParams))
		t.Run("GetAll",
			txTestWrapper(testGetAll))
		t.Run("Get should return all path segments starting or ending at",
			txTestWrapper(testGetStartsAtEndsAt))
		t.Run("Get should return all path segment with given ifIDs",
			txTestWrapper(testGetWithIntfs))
		t.Run("Get should return all path segment with given HpCfgIDs",
			txTestWrapper(testGetWithHpCfgIDs))
		t.Run("Get with MinLastUpdate should return only segs that have been modified",
			txTestWrapper(testGetModifiedIDs))
		t.Run("NextQuery",
			txTestWrapper(testNextQuery))
		t.Run("DeleteExpiredNQ",
			tableWrapper(true, testNextQueryDeleteExpired))
		t.Run("DeleteNQ",
			tableWrapper(true, testDeleteNQ))
		t.Run("Rollback", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			prepareCtx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, prepareCtx)
			testRollback(t, ctrl, db)
		})
	})
}

func testDelete(t *testing.T, pathDB TestablePathDB, inTx bool) {
	tests := map[string]struct {
		Setup func(ctx context.Context, t *testing.T, ctrl *gomock.Controller,
			pathDB pathdb.PathDB) *query.Params
		DeleteCount int
	}{
		"Delete by id": {
			Setup: func(ctx context.Context, t *testing.T, ctrl *gomock.Controller,
				pathDB pathdb.PathDB) *query.Params {
				TS := uint32(10)
				pseg, segID := AllocPathSegment(t, ctrl, ifs1, TS)
				InsertSeg(t, ctx, pathDB, pseg, hpCfgIDs)
				return &query.Params{SegIDs: []common.RawBytes{segID}}
			},
			DeleteCount: 1,
		},
		"Delete by interfaces": {
			Setup: func(ctx context.Context, t *testing.T, ctrl *gomock.Controller,
				pathDB pathdb.PathDB) *query.Params {
				TS := uint32(10)
				pseg, _ := AllocPathSegment(t, ctrl, ifs1, TS)
				InsertSeg(t, ctx, pathDB, pseg, hpCfgIDs)
				pseg, _ = AllocPathSegment(t, ctrl, ifs2, TS)
				InsertSeg(t, ctx, pathDB, pseg, hpCfgIDs)
				return &query.Params{
					Intfs: []*query.IntfSpec{&ifspecs[0]},
				}
			},
			DeleteCount: 1,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			pathDB.Prepare(t, ctx)

			params := test.Setup(ctx, t, ctrl, pathDB)
			var deleted int
			if inTx {
				tx, err := pathDB.BeginTransaction(ctx, nil)
				require.NoError(t, err)
				deleted, err = tx.Delete(ctx, params)
				require.NoError(t, err)
				require.NoError(t, tx.Commit())
			} else {
				var err error
				deleted, err = pathDB.Delete(ctx, params)
				require.NoError(t, err)
			}
			assert.Equal(t, test.DeleteCount, deleted)
		})
	}
}

func testInsertWithHpCfgIDsFull(t *testing.T, ctrl *gomock.Controller, pathDB pathdb.ReadWrite) {
	TS := uint32(10)
	pseg, segID := AllocPathSegment(t, ctrl, ifs1, TS)

	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	// Call
	inserted, err := pathDB.InsertWithHPCfgIDs(ctx, seg.NewMeta(pseg, segType), hpCfgIDs)
	require.NoError(t, err)
	// Check return value.
	assert.Equal(t, 1, inserted, "Inserted")
	// Check Insert.
	res, err := pathDB.Get(ctx, &query.Params{SegIDs: []common.RawBytes{segID}})
	require.NoError(t, err)
	checkResult(t, res, pseg, hpCfgIDs)
}

func testUpdateExisting(t *testing.T, ctrl *gomock.Controller, pathDB pathdb.ReadWrite) {
	oldTS := uint32(10)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	oldSeg, segID := AllocPathSegment(t, ctrl, ifs1, oldTS)
	newTS := uint32(20)
	newSeg, newSegID := AllocPathSegment(t, ctrl, ifs1, newTS)
	assert.Equal(t, segID, newSegID, "IDs should match")
	InsertSeg(t, ctx, pathDB, oldSeg, hpCfgIDs[:1])
	// Call
	inserted := InsertSeg(t, ctx, pathDB, newSeg, hpCfgIDs)
	// Check return value.
	assert.Equal(t, 1, inserted, "Inserted")
	// Check Insert
	res, err := pathDB.Get(ctx, &query.Params{SegIDs: []common.RawBytes{segID}})
	require.NoError(t, err)
	checkResult(t, res, newSeg, hpCfgIDs)
}

func testUpdateOlderIgnored(t *testing.T, ctrl *gomock.Controller, pathDB pathdb.ReadWrite) {
	newTS := uint32(20)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	newSeg, newSegID := AllocPathSegment(t, ctrl, ifs1, newTS)
	oldTS := uint32(10)
	oldSeg, oldSegId := AllocPathSegment(t, ctrl, ifs1, oldTS)
	assert.Equal(t, newSegID, oldSegId, "IDs should match")
	InsertSeg(t, ctx, pathDB, newSeg, hpCfgIDs)
	// Call
	inserted := InsertSeg(t, ctx, pathDB, oldSeg, hpCfgIDs[:1])
	// Check return value.
	assert.Equal(t, 0, inserted, "Inserted")
	// Check Insert
	res, err := pathDB.Get(ctx, &query.Params{SegIDs: []common.RawBytes{newSegID}})
	require.NoError(t, err)
	checkResult(t, res, newSeg, hpCfgIDs)
}

func testUpdateIntfToSeg(t *testing.T, ctrl *gomock.Controller, pathDB pathdb.ReadWrite) {
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	ps, _ := AllocPathSegment(t, ctrl, ifs1, uint32(20))
	InsertSeg(t, ctx, pathDB, ps, hpCfgIDs)
	checkInterfacesPresent(t, ctx, ps.ASEntries, pathDB)
	// Create a new segment with an additional peer entry.
	info := &spath.InfoField{
		TsInt: uint32(30),
		ISD:   1,
		Hops:  3,
	}
	newPs, err := seg.NewSeg(info)
	require.NoError(t, err)
	hfr := make([]byte, 8)
	hf := spath.HopField{
		ConsIngress: common.IFIDType(common.IFIDType(23)),
		ExpTime:     spath.DefaultHopFExpiry,
	}
	hf.Write(hfr)
	he := allocHopEntry(ia331, ia332, hfr)
	asEntries := ps.ASEntries
	asEntries[1].HopEntries = append(asEntries[1].HopEntries, he)

	signer := mock_seg.NewMockSigner(ctrl)
	signer.EXPECT().Sign(gomock.AssignableToTypeOf(common.RawBytes{})).Return(
		&proto.SignS{}, nil).AnyTimes()
	for _, asEntry := range asEntries {
		err = newPs.AddASEntry(asEntry, signer)
		require.NoError(t, err)
	}
	InsertSeg(t, ctx, pathDB, newPs, hpCfgIDs)
	checkInterfacesPresent(t, ctx, newPs.ASEntries, pathDB)
	// Now check that the new interface is removed again.
	ps, _ = AllocPathSegment(t, ctrl, ifs1, uint32(40))
	InsertSeg(t, ctx, pathDB, ps, hpCfgIDs)
	checkInterfacesPresent(t, ctx, ps.ASEntries, pathDB)
	checkInterface(t, ctx, newPs.ASEntries[1].IA(), hf.ConsIngress, pathDB, false)
}

func testDeleteExpired(t *testing.T, ctrl *gomock.Controller, pathDB pathdb.ReadWrite) {
	ts1 := uint32(10)
	ts2 := uint32(20)
	// defaultExp is the default expiry of the hopfields.
	defaultExp := spath.DefaultHopFExpiry.ToDuration()
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	pseg1, _ := AllocPathSegment(t, ctrl, ifs1, ts1)
	pseg2, _ := AllocPathSegment(t, ctrl, ifs2, ts2)
	InsertSeg(t, ctx, pathDB, pseg1, hpCfgIDs)
	InsertSeg(t, ctx, pathDB, pseg2, hpCfgIDs)
	deleted, err := pathDB.DeleteExpired(ctx, time.Unix(10, 0).Add(defaultExp))
	require.NoError(t, err)
	assert.Equal(t, 0, deleted, "Deleted")
	deleted, err = pathDB.DeleteExpired(ctx, time.Unix(20, 0).Add(defaultExp))
	require.NoError(t, err)
	assert.Equal(t, 1, deleted, "Deleted")
	deleted, err = pathDB.DeleteExpired(ctx, time.Unix(30, 0).Add(defaultExp))
	require.NoError(t, err)
	assert.Equal(t, 1, deleted, "Deleted")
}

func testGetMixed(t *testing.T, ctrl *gomock.Controller, pathDB pathdb.ReadWrite) {
	// Setup
	TS := uint32(10)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	pseg1, segID1 := AllocPathSegment(t, ctrl, ifs1, TS)
	pseg2, _ := AllocPathSegment(t, ctrl, ifs2, TS)
	InsertSeg(t, ctx, pathDB, pseg1, hpCfgIDs)
	InsertSeg(t, ctx, pathDB, pseg2, hpCfgIDs[:1])
	params := &query.Params{
		SegIDs:   []common.RawBytes{segID1},
		SegTypes: []proto.PathSegType{proto.PathSegType_up},
	}
	// Call
	res, err := pathDB.Get(ctx, params)
	require.NoError(t, err)
	resSegID, _ := res[0].Seg.ID()
	assert.Equal(t, 1, len(res), "Result count")
	assert.Equal(t, segID1, resSegID, "SegIDs match")
	checkSameHpCfgs(t, "HpCfgIDs match", res[0].HpCfgIDs, hpCfgIDs)
}

func testGetNilParams(t *testing.T, ctrl *gomock.Controller, pathDB pathdb.ReadWrite) {
	// Setup
	TS := uint32(10)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	pseg1, segID1 := AllocPathSegment(t, ctrl, ifs1, TS)
	pseg2, segID2 := AllocPathSegment(t, ctrl, ifs2, TS)
	InsertSeg(t, ctx, pathDB, pseg1, hpCfgIDs)
	InsertSeg(t, ctx, pathDB, pseg2, hpCfgIDs[:1])
	// Call
	res, err := pathDB.Get(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, 2, len(res), "Result count")
	for _, r := range res {
		resSegID, _ := r.Seg.ID()
		if bytes.Compare(resSegID, segID1) == 0 {
			checkSameHpCfgs(t, "HpCfgIDs match", r.HpCfgIDs, hpCfgIDs)
		} else if bytes.Compare(resSegID, segID2) == 0 {
			checkSameHpCfgs(t, "HpCfgIDs match", r.HpCfgIDs, hpCfgIDs[:1])
		} else {
			t.Fatal("Unexpected result", "seg", r.Seg)
		}
	}
}

func testGetAll(t *testing.T, ctrl *gomock.Controller, pathDB pathdb.ReadWrite) {
	// Setup
	TS := uint32(10)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()

	// Empty db should return an empty chan
	resChan, err := pathDB.GetAll(ctx)
	require.NoError(t, err)
	res, more := <-resChan
	assert.Equal(t, query.ResultOrErr{}, res, "No result expected")
	assert.False(t, more, "No more entries expected")

	pseg1, segID1 := AllocPathSegment(t, ctrl, ifs1, TS)
	pseg2, segID2 := AllocPathSegment(t, ctrl, ifs2, TS)
	InsertSeg(t, ctx, pathDB, pseg1, hpCfgIDs)
	InsertSeg(t, ctx, pathDB, pseg2, hpCfgIDs[:1])

	resChan, err = pathDB.GetAll(ctx)
	require.NoError(t, err)
	for r := range resChan {
		assert.NoError(t, r.Err)
		resSegID, _ := r.Result.Seg.ID()
		if bytes.Compare(resSegID, segID1) == 0 {
			checkSameHpCfgs(t, "HpCfgIDs match", r.Result.HpCfgIDs, hpCfgIDs)
		} else if bytes.Compare(resSegID, segID2) == 0 {
			checkSameHpCfgs(t, "HpCfgIDs match", r.Result.HpCfgIDs, hpCfgIDs[:1])
		} else {
			t.Fatal("Unexpected result", "seg", r.Result.Seg)
		}
	}
}

func testGetStartsAtEndsAt(t *testing.T, ctrl *gomock.Controller, pathDB pathdb.ReadWrite) {
	// Setup
	TS := uint32(10)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	pseg1, _ := AllocPathSegment(t, ctrl, ifs1, TS)
	pseg2, _ := AllocPathSegment(t, ctrl, ifs2, TS)
	InsertSeg(t, ctx, pathDB, pseg1, hpCfgIDs)
	InsertSeg(t, ctx, pathDB, pseg2, hpCfgIDs[:1])
	// Call
	res, err := pathDB.Get(ctx, &query.Params{StartsAt: []addr.IA{ia330, ia332}})
	require.NoError(t, err)
	assert.Equal(t, 2, len(res), "Result count")
	res, err = pathDB.Get(ctx, &query.Params{EndsAt: []addr.IA{ia330, ia332}})
	require.NoError(t, err)
	assert.Equal(t, 2, len(res), "Result count")
}

func testGetWithIntfs(t *testing.T, ctrl *gomock.Controller, pathDB pathdb.ReadWrite) {
	// Setup
	TS := uint32(10)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	pseg1, _ := AllocPathSegment(t, ctrl, ifs1, TS)
	pseg2, _ := AllocPathSegment(t, ctrl, ifs2, TS)
	InsertSeg(t, ctx, pathDB, pseg1, hpCfgIDs)
	InsertSeg(t, ctx, pathDB, pseg2, hpCfgIDs[:1])
	params := &query.Params{
		Intfs: []*query.IntfSpec{
			{IA: ia330, IfID: 5},
			{IA: ia332, IfID: 2},
		},
	}
	// Call
	res, err := pathDB.Get(ctx, params)
	require.NoError(t, err)
	assert.Equal(t, 2, len(res), "Result count")
}

func testGetWithHpCfgIDs(t *testing.T, ctrl *gomock.Controller, pathDB pathdb.ReadWrite) {
	// Setup
	TS := uint32(10)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	pseg1, _ := AllocPathSegment(t, ctrl, ifs1, TS)
	pseg2, _ := AllocPathSegment(t, ctrl, ifs2, TS)
	InsertSeg(t, ctx, pathDB, pseg1, hpCfgIDs)
	InsertSeg(t, ctx, pathDB, pseg2, hpCfgIDs[:1])
	params := &query.Params{
		HpCfgIDs: hpCfgIDs[1:],
	}
	// Call
	res, err := pathDB.Get(ctx, params)
	require.NoError(t, err)
	assert.Equal(t, 1, len(res), "Result count")
}

func testGetModifiedIDs(t *testing.T, ctrl *gomock.Controller, pathDB pathdb.ReadWrite) {
	// Setup
	TS := uint32(10)
	now := time.Now()
	tAfter := now.Add(time.Second)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	pseg1, _ := AllocPathSegment(t, ctrl, ifs1, TS)
	pseg2, _ := AllocPathSegment(t, ctrl, ifs2, TS)
	InsertSeg(t, ctx, pathDB, pseg1, hpCfgIDs)
	InsertSeg(t, ctx, pathDB, pseg2, hpCfgIDs[:1])
	q := &query.Params{
		MinLastUpdate: &tAfter,
	}
	res, err := pathDB.Get(ctx, q)
	require.NoError(t, err)
	assert.Equal(t, 0, len(res), "Result count")
	tBefore := now.Add(-5 * time.Second)
	q = &query.Params{
		MinLastUpdate: &tBefore,
	}
	res, err = pathDB.Get(ctx, q)
	require.NoError(t, err)
	assert.Equal(t, 2, len(res), "Result count")
	expectID1, err := pseg1.ID()
	require.NoError(t, err)
	id1, err := res[0].Seg.ID()
	require.NoError(t, err)
	assert.Equal(t, id1, expectID1, "ID 1")
	expectedID2, err := pseg2.ID()
	require.NoError(t, err)
	id2, err := res[1].Seg.ID()
	require.NoError(t, err)
	assert.Equal(t, id2, expectedID2, "ID 2")
}

func testNextQuery(t *testing.T, _ *gomock.Controller, pathDB pathdb.ReadWrite) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	src := xtest.MustParseIA("1-ff00:0:111")
	dst := xtest.MustParseIA("1-ff00:0:133")
	oldT := time.Now().Add(-10 * time.Second)
	updated, err := pathDB.InsertNextQuery(ctx, src, dst, nil, oldT)
	require.NoError(t, err)
	assert.True(t, updated, "Should Insert new")
	dbT, err := pathDB.GetNextQuery(ctx, src, dst, nil)
	require.NoError(t, err)
	assert.Equal(t, oldT.Unix(), dbT.Unix(), "Should return inserted time")
	newT := time.Now()
	updated, err = pathDB.InsertNextQuery(ctx, src, dst, nil, newT)
	require.NoError(t, err)
	assert.True(t, updated, "Should Update existing")
	dbT, err = pathDB.GetNextQuery(ctx, src, dst, nil)
	require.NoError(t, err)
	assert.Equal(t, newT.Unix(), dbT.Unix(), "Should return updated time")
	updated, err = pathDB.InsertNextQuery(ctx, src, dst, nil, oldT)
	require.NoError(t, err)
	assert.False(t, updated, "Should not update to older")
	dbT, err = pathDB.GetNextQuery(ctx, src, dst, nil)
	require.NoError(t, err)
	assert.Equal(t, newT.Unix(), dbT.Unix(), "Should return updated time")
	// with policy
	dbT, err = pathDB.GetNextQuery(ctx, src, dst, policy(t))
	require.NoError(t, err)
	assert.Zero(t, dbT, "Should be zero")
	updated, err = pathDB.InsertNextQuery(ctx, src, dst, policy(t), oldT)
	require.NoError(t, err)
	assert.True(t, updated, "Should Insert new")
	updated, err = pathDB.InsertNextQuery(ctx, src, dst, policy(t), oldT)
	require.NoError(t, err)
	assert.False(t, updated, "Should not update existing")
	dbT, err = pathDB.GetNextQuery(ctx, src, dst, policy(t))
	require.NoError(t, err)
	assert.Equal(t, oldT.Unix(), dbT.Unix(), "Should return inserted time")
	// other dst
	dbT, err = pathDB.GetNextQuery(ctx, src, xtest.MustParseIA("1-ff00:0:122"), nil)
	require.NoError(t, err)
	assert.Zero(t, dbT)
	dbT, err = pathDB.GetNextQuery(ctx, xtest.MustParseIA("1-ff00:0:122"), dst, nil)
	require.NoError(t, err)
	assert.Zero(t, dbT)
	ctx, cancelF = context.WithDeadline(context.Background(), time.Now().Add(-3*time.Second))
	defer cancelF()
	_, err = pathDB.GetNextQuery(ctx, src, xtest.MustParseIA("1-ff00:0:122"), nil)
	assert.Error(t, err)
}

// nqDescriptor describes a next query entry.
type nqDescriptor struct {
	Src    addr.IA
	Dst    addr.IA
	Policy *pathpol.Policy
}

func testNextQueryDeleteExpired(t *testing.T, pathDB TestablePathDB, inTx bool) {
	ia110 := xtest.MustParseIA("1-ff00:0:110")
	ia120 := xtest.MustParseIA("1-ff00:0:120")
	ia130 := xtest.MustParseIA("1-ff00:0:130")

	tests := map[string]struct {
		PrepareDB func(t *testing.T, ctx context.Context,
			now time.Time, pathDB pathdb.ReadWrite)
		ExpectedDeleted   int
		ExpectedRemaining []nqDescriptor
	}{
		"Empty table, no deletions": {
			PrepareDB: func(t *testing.T, ctx context.Context,
				now time.Time, pathDB pathdb.ReadWrite) {
			},
		},
		"Table with non expired entry no deletions": {
			PrepareDB: func(t *testing.T, ctx context.Context,
				now time.Time, pathDB pathdb.ReadWrite) {

				_, err := pathDB.InsertNextQuery(ctx, ia110, ia110, nil, now.Add(time.Minute))
				require.NoError(t, err)
			},
			ExpectedRemaining: []nqDescriptor{{ia110, ia110, nil}},
		},
		"Table with 2 old entries and 1 new entry -> 2 deletions": {
			PrepareDB: func(t *testing.T, ctx context.Context,
				now time.Time, pathDB pathdb.ReadWrite) {

				_, err := pathDB.InsertNextQuery(ctx, ia110, ia110, nil, now.Add(-time.Minute))
				require.NoError(t, err)
				_, err = pathDB.InsertNextQuery(ctx, ia110, ia120, nil, now.Add(-time.Minute))
				require.NoError(t, err)
				_, err = pathDB.InsertNextQuery(ctx, ia110, ia130, nil, now)
				require.NoError(t, err)
			},
			ExpectedDeleted:   2,
			ExpectedRemaining: []nqDescriptor{{ia110, ia130, nil}},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			pathDB.Prepare(t, ctx)

			now := time.Now()
			var deleted int
			test.PrepareDB(t, ctx, now, pathDB)
			if inTx {
				tx, err := pathDB.BeginTransaction(ctx, nil)
				require.NoError(t, err)
				deleted, err = tx.DeleteExpiredNQ(ctx, now)
				require.NoError(t, err)
				require.NoError(t, tx.Commit())
			} else {
				var err error
				deleted, err = pathDB.DeleteExpiredNQ(ctx, now)
				assert.NoError(t, err)
			}
			assert.Equal(t, test.ExpectedDeleted, deleted)
			for _, nq := range test.ExpectedRemaining {
				nextQuery, err := pathDB.GetNextQuery(ctx, nq.Src, nq.Dst, nq.Policy)
				assert.NoError(t, err, "Expected NQ %v to be in DB", nq)
				assert.NotZero(t, nextQuery, "Expected NQ %v to be in DB", nq)
			}
		})
	}
}

func testDeleteNQ(t *testing.T, pathDB TestablePathDB, inTx bool) {
	ia110 := xtest.MustParseIA("1-ff00:0:110")
	ia120 := xtest.MustParseIA("1-ff00:0:120")
	ia130 := xtest.MustParseIA("1-ff00:0:130")
	pol := policy(t)

	insertStdEntries := func(t *testing.T, ctx context.Context, pathDB pathdb.ReadWrite) {
		now := time.Now()
		_, err := pathDB.InsertNextQuery(ctx, ia110, ia110, nil, now.Add(time.Minute))
		require.NoError(t, err)
		_, err = pathDB.InsertNextQuery(ctx, ia110, ia120, nil, now.Add(time.Minute))
		require.NoError(t, err)
		_, err = pathDB.InsertNextQuery(ctx, ia120, ia130, nil, now.Add(time.Minute))
		require.NoError(t, err)
		_, err = pathDB.InsertNextQuery(ctx, ia120, ia130, pol, now.Add(time.Minute))
		require.NoError(t, err)
	}

	tests := map[string]struct {
		PrepareDB         func(t *testing.T, ctx context.Context, pathDB pathdb.ReadWrite)
		Src               addr.IA
		Dst               addr.IA
		Policy            *pathpol.Policy
		ExpectedDeleted   int
		ExpectedRemaining []nqDescriptor
	}{
		"Empty DB -> no deletions": {
			PrepareDB: func(t *testing.T, ctx context.Context, pathDB pathdb.ReadWrite) {},
		},
		"Full DB, delete all -> deletes all": {
			PrepareDB:       insertStdEntries,
			ExpectedDeleted: 4,
		},
		"Full DB, delete src -> deletes all with matching src": {
			PrepareDB:         insertStdEntries,
			Src:               ia120,
			ExpectedDeleted:   2,
			ExpectedRemaining: []nqDescriptor{{ia110, ia110, nil}, {ia110, ia120, nil}},
		},
		"Full DB, delete dst -> deletes all with matching dst": {
			PrepareDB:       insertStdEntries,
			Dst:             ia120,
			ExpectedDeleted: 1,
			ExpectedRemaining: []nqDescriptor{
				{ia110, ia110, nil}, {ia120, ia130, nil}, {ia120, ia130, pol}},
		},
		"Full DB, delete pol -> deletes all with matching policy": {
			PrepareDB:       insertStdEntries,
			Policy:          pol,
			ExpectedDeleted: 1,
			ExpectedRemaining: []nqDescriptor{
				{ia110, ia110, nil}, {ia110, ia120, nil}, {ia120, ia130, nil}},
		},
		"Full DB, delete src,dst -> deletes all with matching src & dst": {
			PrepareDB:       insertStdEntries,
			Src:             ia110,
			Dst:             ia110,
			ExpectedDeleted: 1,
			ExpectedRemaining: []nqDescriptor{
				{ia110, ia120, nil}, {ia120, ia130, nil}, {ia120, ia130, pol}},
		},
		"Not matching query -> deletes nothing": {
			PrepareDB: insertStdEntries,
			Src:       ia110,
			Policy:    pol,
			ExpectedRemaining: []nqDescriptor{
				{ia110, ia110, nil}, {ia110, ia120, nil}, {ia120, ia130, nil}, {ia120, ia130, pol}},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			pathDB.Prepare(t, ctx)

			var deleted int
			test.PrepareDB(t, ctx, pathDB)
			if inTx {
				tx, err := pathDB.BeginTransaction(ctx, nil)
				require.NoError(t, err)
				deleted, err = tx.DeleteNQ(ctx, test.Src, test.Dst, test.Policy)
				require.NoError(t, err)
				require.NoError(t, tx.Commit())
			} else {
				var err error
				deleted, err = pathDB.DeleteNQ(ctx, test.Src, test.Dst, test.Policy)
				assert.NoError(t, err)
			}
			assert.Equal(t, test.ExpectedDeleted, deleted)
			for _, nq := range test.ExpectedRemaining {
				nextQuery, err := pathDB.GetNextQuery(ctx, nq.Src, nq.Dst, nq.Policy)
				assert.NoError(t, err, "Expected NQ %v to be in DB", nq)
				assert.NotZero(t, nextQuery, "Expected NQ %v to be in DB", nq)
			}
		})
	}
}

func testRollback(t *testing.T, ctrl *gomock.Controller, pathDB pathdb.PathDB) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	tx, err := pathDB.BeginTransaction(ctx, nil)
	require.NoError(t, err)
	pseg, _ := AllocPathSegment(t, ctrl, ifs1, uint32(10))
	assert.Equal(t, 1, InsertSeg(t, ctx, tx, pseg, hpCfgIDs), "Insert should succeed")
	err = tx.Rollback()
	assert.NoError(t, err)
	segChan, err := pathDB.GetAll(ctx)
	assert.NoError(t, err)
	res, more := <-segChan
	assert.Equal(t, query.ResultOrErr{}, res, "No entries expected")
	assert.False(t, more, "No more entries expected")
}

func AllocPathSegment(t *testing.T, ctrl *gomock.Controller, ifs []uint64,
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
	require.NoError(t, err)
	signer := mock_seg.NewMockSigner(ctrl)
	signer.EXPECT().Sign(gomock.AssignableToTypeOf(common.RawBytes{})).Return(
		&proto.SignS{}, nil).AnyTimes()
	for _, ase := range ases {
		err := pseg.AddASEntry(ase, signer)
		require.NoError(t, err)
	}
	segID, err := pseg.ID()
	require.NoError(t, err)
	_, err = pseg.FullId()
	require.NoError(t, err)
	return pseg, segID
}

func allocHopEntry(inIA, outIA addr.IA, hopF common.RawBytes) *seg.HopEntry {
	return &seg.HopEntry{
		RawInIA:     inIA.IAInt(),
		RawOutIA:    outIA.IAInt(),
		RawHopField: hopF,
	}
}

func InsertSeg(t *testing.T, ctx context.Context, pathDB pathdb.ReadWrite,
	pseg *seg.PathSegment, hpCfgIDs []*query.HPCfgID) int {

	inserted, err := pathDB.InsertWithHPCfgIDs(ctx, seg.NewMeta(pseg, segType), hpCfgIDs)
	require.NoError(t, err)
	return inserted
}

func checkResult(t *testing.T, results []*query.Result, expectedSeg *seg.PathSegment,
	hpCfgsIds []*query.HPCfgID) {

	assert.Equal(t, 1, len(results), "Expect one result")
	// Make sure the segment is properly initialized.
	_, err := results[0].Seg.ID()
	require.NoError(t, err)
	_, err = results[0].Seg.FullId()
	require.NoError(t, err)
	assert.Equal(t, expectedSeg, results[0].Seg, "Segment should match")
	checkSameHpCfgs(t, "HiddenPath Ids should match", results[0].HpCfgIDs, hpCfgsIds)
}

func checkSameHpCfgs(t *testing.T, msg string, actual, expected []*query.HPCfgID) {
	sort.Slice(actual, func(i, j int) bool {
		return actual[i].IA.I < actual[j].IA.I ||
			actual[i].IA.I == actual[j].IA.I && actual[i].IA.A < actual[j].IA.A ||
			actual[i].IA.Equal(actual[j].IA) && actual[i].ID < actual[j].ID
	})
	assert.Equal(t, expected, actual, msg)
}

func checkInterfacesPresent(t *testing.T, ctx context.Context,
	expectedHopEntries []*seg.ASEntry, pathDB pathdb.ReadWrite) {

	for _, asEntry := range expectedHopEntries {
		for _, hopEntry := range asEntry.HopEntries {
			hof, err := hopEntry.HopField()
			require.NoError(t, err)
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
	pathDB pathdb.ReadWrite, present bool) {

	r, err := pathDB.Get(ctx, &query.Params{
		Intfs: []*query.IntfSpec{
			{
				IA:   ia,
				IfID: ifId,
			},
		},
	})
	require.NoError(t, err)
	if present {
		assert.Equal(t, 1, len(r), fmt.Sprintf("Interface should be present: %v#%d", ia, ifId))
	} else {
		assert.Zero(t, len(r), (fmt.Sprintf("Interface should not be present: %v#%d", ia, ifId)))
	}
}

func policy(t *testing.T) *pathpol.Policy {
	acl, err := pathpol.NewACL(&pathpol.ACLEntry{Action: pathpol.Allow})
	require.NoError(t, err)
	return pathpol.NewPolicy("Test allow all", acl, nil, nil)
}
