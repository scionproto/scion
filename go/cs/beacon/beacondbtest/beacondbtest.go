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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/xtest/graph"
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
	testWrapper := func(test func(*testing.T, *gomock.Controller, beacon.DB)) func(t *testing.T) {
		return func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			prepareCtx, cancelF := context.WithTimeout(context.Background(), 2*timeout)
			defer cancelF()
			db.Prepare(t, prepareCtx)
			test(t, ctrl, db)
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
	t.Run("CandidateBeacons returns the expected beacons", func(t *testing.T) {
		testCandidateBeacons(t, db)
	})
}

func testBeaconSources(t *testing.T, ctrl *gomock.Controller, db beacon.DB) {
	for i, info := range [][]IfInfo{Info3, Info2, Info1} {
		InsertBeacon(t, ctrl, db, info, 12, uint32(i), beacon.UsageProp)
	}
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	ias, err := db.BeaconSources(ctx)
	require.NoError(t, err)
	assert.ElementsMatch(t, []addr.IA{ia311, ia330}, ias)
}

func testInsertBeacon(t *testing.T, ctrl *gomock.Controller, db beacon.DB) {
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
		assert.NoError(t, err)
		assert.Empty(t, results)
	}
}

func testUpdateExisting(t *testing.T, ctrl *gomock.Controller, db beacon.DB) {
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
		assert.NoError(t, err)
		assert.Empty(t, results)
	}
}

func testUpdateOlderIgnored(t *testing.T, ctrl *gomock.Controller, db beacon.DB) {
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
		assert.NoError(t, err)
		assert.Empty(t, results)
	}
}

func testCandidateBeacons(t *testing.T, db Testable) {
	rootCtrl := gomock.NewController(t)
	defer rootCtrl.Finish()
	// Insert beacons from longest to shortest path such that the insertion
	// order is not sorted the same as the expected outcome.
	var beacons []beacon.Beacon
	insertBeacons := func(t *testing.T, db beacon.DB) {
		for i, info := range [][]IfInfo{Info3, Info2, Info1} {
			b := InsertBeacon(t, rootCtrl, db, info, 12, uint32(i), beacon.UsageProp)
			// Prepend to get beacons sorted from shortest to longest path.
			beacons = append([]beacon.Beacon{b}, beacons...)
		}
	}
	insertBeacons(t, db)
	tests := map[string]struct {
		PrepareDB func(t *testing.T, ctx context.Context, db beacon.DB)
		Src       addr.IA
		Expected  []beacon.Beacon
	}{
		"If no source ISD-AS is specified, all beacons are returned": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beacon.DB) {
				insertBeacons(t, db)
			},
			Expected: beacons,
		},
		"Only beacons with matching source ISD-AS are returned, if specified": {
			PrepareDB: func(t *testing.T, ctx context.Context, db beacon.DB) {
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

// CheckResult checks that the expected beacon is returned in results, and
// that it is the only returned beacon
func CheckResult(t *testing.T, results []beacon.BeaconOrErr, expected beacon.Beacon) {
	CheckResults(t, results, []beacon.Beacon{expected})
}

func CheckResults(t *testing.T, results []beacon.BeaconOrErr, expectedBeacons []beacon.Beacon) {
	for i, expected := range expectedBeacons {
		res := results[i]
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
	}
}

func InsertBeacon(t *testing.T, ctrl *gomock.Controller, db beacon.DB, ases []IfInfo,
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
