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

package dbtest

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/pathdb/query"
)

var (
	ia330 = addr.MustIAFrom(1, 0xff0000000330)
	ia311 = addr.MustIAFrom(1, 0xff0000000311)
	ia331 = addr.MustIAFrom(1, 0xff0000000331)
	ia332 = addr.MustIAFrom(1, 0xff0000000332)

	ifs1 = []uint64{0, 5, 2, 3, 6, 3, 1, 0}
	ifs2 = []uint64{0, 4, 2, 3, 1, 3, 2, 0}

	hpGroupIDs = []uint64{
		0,
		0xffffffffffffffff,
	}
	segType = seg.TypeUp

	timeout = 5 * time.Second
)

// TestablePathDB extends the path db interface with methods that are needed
// for testing.
type TestablePathDB interface {
	pathdb.DB
	// Prepare should reset the internal state so that the DB is empty and is
	// ready to be tested.
	Prepare(t *testing.T, ctx context.Context)
}

// TestPathDB should be used to test any implementation of the PathDB
// interface. An implementation of the PathDB interface should at least have
// one test method that calls this test-suite.
func TestPathDB(t *testing.T, db TestablePathDB) {
	testWrapper := func(test func(*testing.T,
		pathdb.ReadWrite)) func(t *testing.T) {

		return func(t *testing.T) {
			prepareCtx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, prepareCtx)
			test(t, db)
		}
	}
	t.Run("InsertWithHPGroupID should correctly insert a new segment",
		testWrapper(testInsertWithHPGroupIDsFull))
	t.Run("InsertWithHPGroupID should correctly update a new segment",
		testWrapper(testUpdateExisting))
	t.Run("InsertWithHPGroupID should correctly ignore an older segment",
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
	t.Run("Get should return all path segment with given HPGroupIDs",
		testWrapper(testGetWithHPGroupIDs))
	t.Run("NextQuery",
		testWrapper(testNextQuery))

	txTestWrapper := func(test func(*testing.T,
		pathdb.ReadWrite)) func(t *testing.T) {

		return func(t *testing.T) {
			ctx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, ctx)
			tx, err := db.BeginTransaction(ctx, nil)
			require.NoError(t, err)
			test(t, tx)
			err = tx.Commit()
			require.NoError(t, err)
		}
	}
	t.Run("WithTransaction", func(t *testing.T) {
		t.Run("InsertWithHPGroupID should correctly insert a new segment",
			txTestWrapper(testInsertWithHPGroupIDsFull))
		t.Run("InsertWithHPGroupID should correctly update a new segment",
			txTestWrapper(testUpdateExisting))
		t.Run("InsertWithHPGroupID should correctly ignore an older segment",
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
		t.Run("Get should return all path segment with given HPGroupIDs",
			txTestWrapper(testGetWithHPGroupIDs))
		t.Run("NextQuery",
			txTestWrapper(testNextQuery))
		t.Run("Rollback", func(t *testing.T) {
			prepareCtx, cancelF := context.WithTimeout(context.Background(), timeout)
			defer cancelF()
			db.Prepare(t, prepareCtx)
			testRollback(t, db)
		})
	})
}

func testInsertWithHPGroupIDsFull(t *testing.T, pathDB pathdb.ReadWrite) {
	TS := uint32(10)
	pseg, segID := AllocPathSegment(t, ifs1, TS)

	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	// Call
	stat, err := pathDB.InsertWithHPGroupIDs(ctx,
		&seg.Meta{Segment: pseg, Type: segType},
		hpGroupIDs,
	)
	require.NoError(t, err)
	// Check return value.
	assert.Equal(t, pathdb.InsertStats{Inserted: 1}, stat, "Inserted")
	// Check Insert.
	res, err := pathDB.Get(ctx, &query.Params{SegIDs: [][]byte{segID}})
	require.NoError(t, err)
	checkResult(t, res, pseg, hpGroupIDs)
}

func testUpdateExisting(t *testing.T, pathDB pathdb.ReadWrite) {
	oldTS := uint32(10)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	oldSeg, segID := AllocPathSegment(t, ifs1, oldTS)
	newTS := uint32(20)
	newSeg, newSegID := AllocPathSegment(t, ifs1, newTS)
	assert.Equal(t, segID, newSegID, "IDs should match")
	stat := InsertSeg(t, ctx, pathDB, oldSeg, hpGroupIDs[:1])
	assert.Equal(t, pathdb.InsertStats{Inserted: 1}, stat)
	// Call
	stat = InsertSeg(t, ctx, pathDB, newSeg, hpGroupIDs)
	// Check return value.
	assert.Equal(t, pathdb.InsertStats{Updated: 1}, stat, "Inserted")
	// Check Insert
	res, err := pathDB.Get(ctx, &query.Params{SegIDs: [][]byte{segID}})
	require.NoError(t, err)
	checkResult(t, res, newSeg, hpGroupIDs)
}

func testUpdateOlderIgnored(t *testing.T, pathDB pathdb.ReadWrite) {
	newTS := uint32(20)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	newSeg, newSegID := AllocPathSegment(t, ifs1, newTS)
	oldTS := uint32(10)
	oldSeg, oldSegId := AllocPathSegment(t, ifs1, oldTS)
	assert.Equal(t, newSegID, oldSegId, "IDs should match")
	stat := InsertSeg(t, ctx, pathDB, newSeg, hpGroupIDs)
	assert.Equal(t, pathdb.InsertStats{Inserted: 1}, stat)
	// Call
	stat = InsertSeg(t, ctx, pathDB, oldSeg, hpGroupIDs[:1])
	// Check return value.
	assert.Equal(t, pathdb.InsertStats{}, stat, "Inserted")
	// Check Insert
	res, err := pathDB.Get(ctx, &query.Params{SegIDs: [][]byte{newSegID}})
	require.NoError(t, err)
	checkResult(t, res, newSeg, hpGroupIDs)
}

func testUpdateIntfToSeg(t *testing.T, pathDB pathdb.ReadWrite) {
	ctx, cancelF := context.WithTimeout(context.Background(), 200*timeout)
	defer cancelF()
	ps, _ := AllocPathSegment(t, ifs1, uint32(20))
	stat := InsertSeg(t, ctx, pathDB, ps, hpGroupIDs)
	require.Equal(t, pathdb.InsertStats{Inserted: 1}, stat)
	checkInterfacesPresent(t, ctx, ps.ASEntries, pathDB)

	// Ensure segment appears to be newer.
	newPS, _ := AllocPathSegment(t, ifs1, uint32(30))

	// Add an additional peer entry.
	newPS.ASEntries[1].PeerEntries = append(newPS.ASEntries[1].PeerEntries, seg.PeerEntry{
		Peer:          ia331,
		PeerInterface: 0, // Does not matter.
		HopField: seg.HopField{
			ConsIngress: 23,
			ConsEgress:  newPS.ASEntries[1].HopEntry.HopField.ConsEgress,
			MAC:         [path.MacLen]byte{},
		},
	})

	stat = InsertSeg(t, ctx, pathDB, newPS, hpGroupIDs)
	require.Equal(t, pathdb.InsertStats{Updated: 1}, stat)
	checkInterfacesPresent(t, ctx, newPS.ASEntries, pathDB)
	// Now check that the new interface is removed again.
	ps, _ = AllocPathSegment(t, ifs1, uint32(40))
	stat = InsertSeg(t, ctx, pathDB, ps, hpGroupIDs)
	require.Equal(t, pathdb.InsertStats{Updated: 1}, stat)
	checkInterfacesPresent(t, ctx, ps.ASEntries, pathDB)
	checkInterface(t, ctx, newPS.ASEntries[1].Local, 23, pathDB, false)
}

func testDeleteExpired(t *testing.T, pathDB pathdb.ReadWrite) {
	ts1 := uint32(10)
	ts2 := uint32(20)
	// defaultExp is the default expiry of the hopfields.
	defaultExp := path.ExpTimeToDuration(63)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	pseg1, _ := AllocPathSegment(t, ifs1, ts1)
	pseg2, _ := AllocPathSegment(t, ifs2, ts2)
	stat := InsertSeg(t, ctx, pathDB, pseg1, hpGroupIDs)
	require.Equal(t, pathdb.InsertStats{Inserted: 1}, stat)
	stat = InsertSeg(t, ctx, pathDB, pseg2, hpGroupIDs)
	require.Equal(t, pathdb.InsertStats{Inserted: 1}, stat)
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

func testGetMixed(t *testing.T, pathDB pathdb.ReadWrite) {
	// Setup
	TS := uint32(10)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	pseg1, segID1 := AllocPathSegment(t, ifs1, TS)
	pseg2, _ := AllocPathSegment(t, ifs2, TS)
	stat := InsertSeg(t, ctx, pathDB, pseg1, hpGroupIDs)
	require.Equal(t, stat, pathdb.InsertStats{Inserted: 1})
	stat = InsertSeg(t, ctx, pathDB, pseg2, hpGroupIDs[:1])
	require.Equal(t, stat, pathdb.InsertStats{Inserted: 1})
	params := &query.Params{
		SegIDs:   [][]byte{segID1},
		SegTypes: []seg.Type{seg.TypeUp},
	}
	// Call
	res, err := pathDB.Get(ctx, params)
	require.NoError(t, err)
	assert.Equal(t, 1, len(res), "Result count")
	assert.Equal(t, segID1, res[0].Seg.ID(), "SegIDs match")
	assert.Equal(t, seg.TypeUp, res[0].Type)
	checkSameHpCfgs(t, "HPGroupIDs match", res[0].HPGroupIDs, hpGroupIDs)
}

func testGetNilParams(t *testing.T, pathDB pathdb.ReadWrite) {
	// Setup
	TS := uint32(10)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	pseg1, segID1 := AllocPathSegment(t, ifs1, TS)
	pseg2, segID2 := AllocPathSegment(t, ifs2, TS)
	stat := InsertSeg(t, ctx, pathDB, pseg1, hpGroupIDs)
	require.Equal(t, stat, pathdb.InsertStats{Inserted: 1})
	stat = InsertSeg(t, ctx, pathDB, pseg2, hpGroupIDs[:1])
	require.Equal(t, stat, pathdb.InsertStats{Inserted: 1})
	// Call
	res, err := pathDB.Get(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, 2, len(res), "Result count")
	for _, r := range res {
		assert.Equal(t, seg.TypeUp, r.Type)
		resSegID := r.Seg.ID()
		if bytes.Equal(resSegID, segID1) {
			checkSameHpCfgs(t, "HPGroupIDs match", r.HPGroupIDs, hpGroupIDs)
		} else if bytes.Equal(resSegID, segID2) {
			checkSameHpCfgs(t, "HPGroupIDs match", r.HPGroupIDs, hpGroupIDs[:1])
		} else {
			t.Fatal("Unexpected result", "seg", r.Seg)
		}
	}
}

func testGetAll(t *testing.T, pathDB pathdb.ReadWrite) {
	// Setup
	TS := uint32(10)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()

	// Empty db should return an empty slice and no error
	s, err := pathDB.GetAll(ctx)
	require.NoError(t, err)
	assert.Empty(t, s, "No result expected")

	pseg1, segID1 := AllocPathSegment(t, ifs1, TS)
	pseg2, segID2 := AllocPathSegment(t, ifs2, TS)
	stat := InsertSeg(t, ctx, pathDB, pseg1, hpGroupIDs)
	require.Equal(t, stat, pathdb.InsertStats{Inserted: 1})
	stat = InsertSeg(t, ctx, pathDB, pseg2, hpGroupIDs[:1])
	require.Equal(t, stat, pathdb.InsertStats{Inserted: 1})

	s, err = pathDB.GetAll(ctx)
	require.NoError(t, err)
	for _, r := range s {
		assert.Equal(t, seg.TypeUp, r.Type)
		resSegID := r.Seg.ID()
		if bytes.Equal(resSegID, segID1) {
			checkSameHpCfgs(t, "HPGroupIDs match", r.HPGroupIDs, hpGroupIDs)
		} else if bytes.Equal(resSegID, segID2) {
			checkSameHpCfgs(t, "HPGroupIDs match", r.HPGroupIDs, hpGroupIDs[:1])
		} else {
			t.Fatal("Unexpected result", "seg", r.Seg)
		}
	}
}

func testGetStartsAtEndsAt(t *testing.T, pathDB pathdb.ReadWrite) {
	// Setup
	TS := uint32(10)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	pseg1, _ := AllocPathSegment(t, ifs1, TS)
	pseg2, _ := AllocPathSegment(t, ifs2, TS)
	stat := InsertSeg(t, ctx, pathDB, pseg1, hpGroupIDs)
	require.Equal(t, stat, pathdb.InsertStats{Inserted: 1})
	stat = InsertSeg(t, ctx, pathDB, pseg2, hpGroupIDs[:1])
	require.Equal(t, stat, pathdb.InsertStats{Inserted: 1})
	// Call
	res, err := pathDB.Get(ctx, &query.Params{StartsAt: []addr.IA{ia330, ia332}})
	require.NoError(t, err)
	assert.Equal(t, 2, len(res), "Result count")
	res, err = pathDB.Get(ctx, &query.Params{EndsAt: []addr.IA{ia330, ia332}})
	require.NoError(t, err)
	assert.Equal(t, 2, len(res), "Result count")
}

func testGetWithIntfs(t *testing.T, pathDB pathdb.ReadWrite) {
	// Setup
	TS := uint32(10)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	pseg1, _ := AllocPathSegment(t, ifs1, TS)
	pseg2, _ := AllocPathSegment(t, ifs2, TS)
	stat := InsertSeg(t, ctx, pathDB, pseg1, hpGroupIDs)
	require.Equal(t, stat, pathdb.InsertStats{Inserted: 1})
	stat = InsertSeg(t, ctx, pathDB, pseg2, hpGroupIDs[:1])
	require.Equal(t, stat, pathdb.InsertStats{Inserted: 1})
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

func testGetWithHPGroupIDs(t *testing.T, pathDB pathdb.ReadWrite) {
	// Setup
	TS := uint32(10)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	pseg1, _ := AllocPathSegment(t, ifs1, TS)
	pseg2, _ := AllocPathSegment(t, ifs2, TS)
	stat := InsertSeg(t, ctx, pathDB, pseg1, hpGroupIDs)
	require.Equal(t, stat, pathdb.InsertStats{Inserted: 1})
	stat = InsertSeg(t, ctx, pathDB, pseg2, hpGroupIDs[:1])
	require.Equal(t, stat, pathdb.InsertStats{Inserted: 1})
	params := &query.Params{
		HPGroupIDs: hpGroupIDs[1:],
	}
	// Call
	res, err := pathDB.Get(ctx, params)
	require.NoError(t, err)
	assert.Equal(t, 1, len(res), "Result count")
}

func testNextQuery(t *testing.T, pathDB pathdb.ReadWrite) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	src := addr.MustParseIA("1-ff00:0:111")
	dst := addr.MustParseIA("1-ff00:0:133")
	oldT := time.Now().Add(-10 * time.Second)
	updated, err := pathDB.InsertNextQuery(ctx, src, dst, oldT)
	require.NoError(t, err)
	assert.True(t, updated, "Should Insert new")
	dbT, err := pathDB.GetNextQuery(ctx, src, dst)
	require.NoError(t, err)
	assert.Equal(t, oldT.Unix(), dbT.Unix(), "Should return inserted time")
	newT := time.Now()
	updated, err = pathDB.InsertNextQuery(ctx, src, dst, newT)
	require.NoError(t, err)
	assert.True(t, updated, "Should Update existing")
	dbT, err = pathDB.GetNextQuery(ctx, src, dst)
	require.NoError(t, err)
	assert.Equal(t, newT.Unix(), dbT.Unix(), "Should return updated time")
	updated, err = pathDB.InsertNextQuery(ctx, src, dst, oldT)
	require.NoError(t, err)
	assert.False(t, updated, "Should not update to older")
	dbT, err = pathDB.GetNextQuery(ctx, src, dst)
	require.NoError(t, err)
	assert.Equal(t, newT.Unix(), dbT.Unix(), "Should return updated time")
	// other dst
	dbT, err = pathDB.GetNextQuery(ctx, src, addr.MustParseIA("1-ff00:0:122"))
	require.NoError(t, err)
	assert.Zero(t, dbT)
	dbT, err = pathDB.GetNextQuery(ctx, addr.MustParseIA("1-ff00:0:122"), dst)
	require.NoError(t, err)
	assert.Zero(t, dbT)
	ctx, cancelF = context.WithDeadline(context.Background(), time.Now().Add(-3*time.Second))
	defer cancelF()
	_, err = pathDB.GetNextQuery(ctx, src, addr.MustParseIA("1-ff00:0:122"))
	assert.Error(t, err)
}

func testRollback(t *testing.T, pathDB pathdb.DB) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	tx, err := pathDB.BeginTransaction(ctx, nil)
	require.NoError(t, err)
	pseg, _ := AllocPathSegment(t, ifs1, uint32(10))
	assert.Equal(t, pathdb.InsertStats{Inserted: 1},
		InsertSeg(t, ctx, tx, pseg, hpGroupIDs), "Insert should succeed")
	err = tx.Rollback()
	assert.NoError(t, err)
	s, err := pathDB.GetAll(ctx)
	assert.NoError(t, err)
	assert.Empty(t, s, "No entries expected")
}

func AllocPathSegment(t *testing.T, ifs []uint64, infoTS uint32) (*seg.PathSegment, []byte) {

	hops := make([]seg.HopField, 0, len(ifs)/2)
	for i := 0; i < len(ifs)/2; i++ {
		hops = append(hops, seg.HopField{
			ConsIngress: uint16(ifs[2*i]),
			ConsEgress:  uint16(ifs[2*i+1]),
			ExpTime:     63,
			MAC:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
		})
	}

	ases := []seg.ASEntry{
		{
			Local: ia330,
			Next:  ia331,
			MTU:   1337,
			HopEntry: seg.HopEntry{
				IngressMTU: 1337,
				HopField:   hops[0],
			},
		},
		{
			Local: ia331,
			Next:  ia332,
			MTU:   1337,
			HopEntry: seg.HopEntry{
				IngressMTU: 1337,
				HopField:   hops[1],
			},
			PeerEntries: []seg.PeerEntry{
				{
					HopField:      hops[2],
					Peer:          ia311,
					PeerInterface: 0,
					PeerMTU:       1337,
				},
			},
		},
		{
			Local: ia332,
			HopEntry: seg.HopEntry{
				IngressMTU: 1337,
				HopField:   hops[3],
			},
		},
	}

	pseg, err := seg.CreateSegment(time.Unix(int64(infoTS), 0), uint16(rand.Int()))
	require.NoError(t, err)
	for _, ase := range ases {
		signer := graph.NewSigner()
		// for testing purposes set the signer timestamp equal to infoTS
		signer.Timestamp = time.Unix(int64(infoTS), 0)
		err := pseg.AddASEntry(context.Background(), ase, signer)
		require.NoError(t, err)
	}
	return pseg, pseg.ID()
}

func InsertSeg(t *testing.T, ctx context.Context, pathDB pathdb.ReadWrite,
	pseg *seg.PathSegment, hpGroupIDs []uint64) pathdb.InsertStats {

	inserted, err := pathDB.InsertWithHPGroupIDs(ctx,
		&seg.Meta{
			Segment: pseg,
			Type:    segType,
		},
		hpGroupIDs,
	)
	require.NoError(t, err)
	return inserted
}

func checkResult(t *testing.T, results query.Results, expectedSeg *seg.PathSegment,
	hpCfgsIds []uint64) {

	require.Equal(t, 1, len(results), "Expect one result")

	assert.Equal(t, expectedSeg.Info.Timestamp, results[0].Seg.Info.Timestamp)
	assert.Equal(t, expectedSeg.MaxIdx(), results[0].Seg.MaxIdx())
	for i := range expectedSeg.ASEntries {
		expected := seg.ASEntry{
			Extensions:  expectedSeg.ASEntries[i].Extensions,
			HopEntry:    expectedSeg.ASEntries[i].HopEntry,
			Local:       expectedSeg.ASEntries[i].Local,
			MTU:         expectedSeg.ASEntries[i].MTU,
			Next:        expectedSeg.ASEntries[i].Next,
			PeerEntries: expectedSeg.ASEntries[i].PeerEntries,
		}
		actual := seg.ASEntry{
			Extensions:  results[0].Seg.ASEntries[i].Extensions,
			HopEntry:    results[0].Seg.ASEntries[i].HopEntry,
			Local:       results[0].Seg.ASEntries[i].Local,
			MTU:         results[0].Seg.ASEntries[i].MTU,
			Next:        results[0].Seg.ASEntries[i].Next,
			PeerEntries: results[0].Seg.ASEntries[i].PeerEntries,
		}
		assert.Equal(t, expected, actual)
	}
	checkSameHpCfgs(t, "HiddenPath Ids should match", results[0].HPGroupIDs, hpCfgsIds)
}

func checkSameHpCfgs(t *testing.T, msg string, actual, expected []uint64) {
	sort.Slice(actual, func(i, j int) bool {
		return actual[i] < actual[j]
	})
	assert.Equal(t, expected, actual, msg)
}

func checkInterfacesPresent(t *testing.T, ctx context.Context,
	expectedHopEntries []seg.ASEntry, pathDB pathdb.ReadWrite) {

	for _, asEntry := range expectedHopEntries {
		hopFields := []seg.HopField{asEntry.HopEntry.HopField}
		for _, peer := range asEntry.PeerEntries {
			hopFields = append(hopFields, peer.HopField)
		}
		for _, hopField := range hopFields {
			if hopField.ConsIngress != 0 {
				checkInterface(t, ctx, asEntry.Local, hopField.ConsIngress, pathDB, true)
			}
			if hopField.ConsEgress != 0 {
				checkInterface(t, ctx, asEntry.Local, hopField.ConsEgress, pathDB, true)
			}
		}
	}
}

func checkInterface(t *testing.T, ctx context.Context, ia addr.IA, ifID uint16,
	pathDB pathdb.ReadWrite, present bool) {

	r, err := pathDB.Get(ctx, &query.Params{
		Intfs: []*query.IntfSpec{
			{
				IA:   ia,
				IfID: iface.ID(ifID),
			},
		},
	})
	require.NoError(t, err)
	if present {
		assert.Equal(t, 1, len(r), fmt.Sprintf("Interface should be present: %v#%d", ia, ifID))
	} else {
		assert.Zero(t, len(r), (fmt.Sprintf("Interface should not be present: %v#%d", ia, ifID)))
	}
}
