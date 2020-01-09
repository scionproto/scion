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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/ctrl/seg/mock_seg"
	"github.com/scionproto/scion/go/lib/spath"
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
			prepareCtx, cancelF := context.WithTimeout(context.Background(), timeout)
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
	defaultExp := spath.DefaultHopFExpiry.ToDuration()
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
			_, err := res.Beacon.Segment.ID()
			require.NoError(t, err)
			_, err = res.Beacon.Segment.FullId()
			require.NoError(t, err)
			assert.Equal(t, expected.Segment, res.Beacon.Segment, "Segment %d should match", i)
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

func InsertBeacon(t *testing.T, ctrl *gomock.Controller, db beacon.DBReadWrite, ases []IfInfo,
	inIfId common.IFIDType, infoTS uint32, allowed beacon.Usage) beacon.Beacon {
	b, _ := AllocBeacon(t, ctrl, ases, inIfId, infoTS)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	_, err := db.InsertBeacon(ctx, b, allowed)
	require.NoError(t, err)
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
	require.NoError(t, err)
	signer := mock_seg.NewMockSigner(ctrl)
	signer.EXPECT().Sign(gomock.AssignableToTypeOf(common.RawBytes{})).Return(
		&proto.SignS{}, nil).AnyTimes()
	for _, entry := range entries {
		err := pseg.AddASEntry(entry, signer)
		require.NoError(t, err)
	}
	segID, err := pseg.ID()
	require.NoError(t, err)
	_, err = pseg.FullId()
	require.NoError(t, err)
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
