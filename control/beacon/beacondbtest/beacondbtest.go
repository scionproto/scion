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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/slayers/path"
)

var (
	IA311 = addr.MustIAFrom(1, 0xff0000000311)
	IA330 = addr.MustIAFrom(1, 0xff0000000330)
	IA331 = addr.MustIAFrom(1, 0xff0000000331)
	IA332 = addr.MustIAFrom(1, 0xff0000000332)
	IA333 = addr.MustIAFrom(1, 0xff0000000333)
	IA334 = addr.MustIAFrom(2, 0xff0000000334)

	Info1 = []IfInfo{
		{
			IA:     IA311,
			Next:   IA330,
			Egress: 10,
		},
	}

	Info2 = []IfInfo{
		{
			IA:     IA330,
			Next:   IA331,
			Egress: 4,
		},
		{
			IA:      IA331,
			Next:    IA332,
			Ingress: 1,
			Egress:  4,
			Peers:   []PeerEntry{{IA: IA311, Ingress: 4}},
		},
	}

	Info3 = []IfInfo{
		{
			IA:     IA330,
			Next:   IA331,
			Egress: 5,
		},
		{
			IA:      IA331,
			Next:    IA332,
			Ingress: 2,
			Egress:  3,
			Peers:   []PeerEntry{{IA: IA311, Ingress: 6}},
		},
		{
			IA:      IA332,
			Next:    IA333,
			Ingress: 1,
			Egress:  7,
		},
	}

	Info4 = []IfInfo{
		{
			IA:     IA334,
			Next:   IA330,
			Egress: 10,
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
	testWrapper := func(test func(*testing.T, beacon.DB)) func(t *testing.T) {
		return func(t *testing.T) {
			prepareCtx, cancelF := context.WithTimeout(context.Background(), 2*timeout)
			defer cancelF()
			db.Prepare(t, prepareCtx)
			test(t, db)
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

func testBeaconSources(t *testing.T, db beacon.DB) {
	for i, info := range [][]IfInfo{Info3, Info2, Info1} {
		InsertBeacon(t, db, info, 12, uint32(i), beacon.UsageProp)
	}
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	ias, err := db.BeaconSources(ctx)
	require.NoError(t, err)
	assert.ElementsMatch(t, []addr.IA{IA311, IA330}, ias)
}

func testInsertBeacon(t *testing.T, db beacon.DB) {
	TS := uint32(10)
	b, _ := AllocBeacon(t, Info3, 12, TS)

	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	inserted, err := db.InsertBeacon(ctx, b, beacon.UsageProp)
	require.NoError(t, err)

	exp := beacon.InsertStats{Inserted: 1, Updated: 0}
	assert.Equal(t, exp, inserted)

	// Fetch the candidate beacons
	results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, 0)
	require.NoError(t, err)

	// There should only be one candidate beacon, and it should match the inserted.
	CheckResult(t, results, b)
	for _, usage := range []beacon.Usage{beacon.UsageUpReg, beacon.UsageDownReg,
		beacon.UsageCoreReg} {
		results, err = db.CandidateBeacons(ctx, 10, usage, 0)
		assert.NoError(t, err)
		assert.Empty(t, results)
	}
}

func testUpdateExisting(t *testing.T, db beacon.DB) {
	oldTS := uint32(10)
	oldB, oldId := AllocBeacon(t, Info3, 12, oldTS)

	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()

	inserted, err := db.InsertBeacon(ctx, oldB, beacon.UsageProp)
	require.NoError(t, err)

	exp := beacon.InsertStats{Inserted: 1, Updated: 0}
	assert.Equal(t, exp, inserted)

	newTS := uint32(20)
	newB, newId := AllocBeacon(t, Info3, 12, newTS)
	assert.Equal(t, oldId, newId, "IDs should match")

	inserted, err = db.InsertBeacon(ctx, newB, beacon.UsageDownReg)
	require.NoError(t, err)

	exp = beacon.InsertStats{Inserted: 0, Updated: 1}
	assert.Equal(t, exp, inserted)

	// Fetch the candidate beacons
	results, err := db.CandidateBeacons(ctx, 10, beacon.UsageDownReg, 0)
	require.NoError(t, err, "CandidateBeacons err")

	// There should only be one candidate beacon, and it should match the inserted.
	CheckResult(t, results, newB)
	for _, usage := range []beacon.Usage{beacon.UsageUpReg, beacon.UsageProp,
		beacon.UsageCoreReg} {
		results, err = db.CandidateBeacons(ctx, 10, usage, 0)
		assert.NoError(t, err)
		assert.Empty(t, results)
	}
}

func testUpdateOlderIgnored(t *testing.T, db beacon.DB) {
	newTS := uint32(20)
	newB, newId := AllocBeacon(t, Info3, 12, newTS)

	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()

	inserted, err := db.InsertBeacon(ctx, newB, beacon.UsageProp)
	require.NoError(t, err)

	exp := beacon.InsertStats{Inserted: 1, Updated: 0}
	assert.Equal(t, exp, inserted, "Inserted new")

	oldTS := uint32(10)
	oldB, oldId := AllocBeacon(t, Info3, 12, oldTS)
	assert.Equal(t, oldId, newId, "IDs should match")

	inserted, err = db.InsertBeacon(ctx, oldB, beacon.UsageDownReg)
	require.NoError(t, err)

	exp = beacon.InsertStats{Inserted: 0, Updated: 0}
	assert.Equal(t, exp, inserted, "Inserted old")
	// Fetch the candidate beacons
	results, err := db.CandidateBeacons(ctx, 10, beacon.UsageProp, 0)
	require.NoError(t, err)
	// There should only be one candidate beacon, and it should match the inserted.
	CheckResult(t, results, newB)
	for _, usage := range []beacon.Usage{beacon.UsageUpReg, beacon.UsageDownReg,
		beacon.UsageCoreReg} {
		results, err = db.CandidateBeacons(ctx, 10, usage, 0)
		assert.NoError(t, err)
		assert.Empty(t, results)
	}
}

func testCandidateBeacons(t *testing.T, db Testable) {
	// Insert beacons from longest to shortest path such that the insertion
	// order is not sorted the same as the expected outcome.
	var beacons []beacon.Beacon
	insertBeacons := func(t *testing.T, db beacon.DB) {
		for i, info := range [][]IfInfo{Info3, Info2, Info1} {
			b := InsertBeacon(t, db, info, 12, uint32(i), beacon.UsageProp)
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
func CheckResult(t *testing.T, results []beacon.Beacon, expected beacon.Beacon) {
	CheckResults(t, results, []beacon.Beacon{expected})
}

// CheckResults checks whether results and expectedBeacons are equivalent.
func CheckResults(t *testing.T, results []beacon.Beacon, expectedBeacons []beacon.Beacon) {
	assert.Equal(t, len(results), len(expectedBeacons),
		"results and expected do not have the same number of beacons")

	for i, expected := range expectedBeacons {
		res := results[i]
		require.NotNil(t, res.Segment, "Beacon %d segment", i)

		// Make sure the segment is properly initialized.
		assert.Equal(t, expected.Segment.Info, res.Segment.Info)
		assert.Equal(t, expected.Segment.MaxIdx(), res.Segment.MaxIdx())
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
				Extensions:  res.Segment.ASEntries[i].Extensions,
				HopEntry:    res.Segment.ASEntries[i].HopEntry,
				Local:       res.Segment.ASEntries[i].Local,
				MTU:         res.Segment.ASEntries[i].MTU,
				Next:        res.Segment.ASEntries[i].Next,
				PeerEntries: res.Segment.ASEntries[i].PeerEntries,
			}
			assert.Equal(t, expected, actual)
		}
		assert.Equal(t, expected.InIfID, res.InIfID, "InIfID %d should match", i)
	}
}

func InsertBeacon(t *testing.T, db beacon.DB, ases []IfInfo,
	inIfID uint16, infoTS uint32, allowed beacon.Usage) beacon.Beacon {
	b, _ := AllocBeacon(t, ases, inIfID, infoTS)
	ctx, cancelF := context.WithTimeout(context.Background(), timeout)
	defer cancelF()
	_, err := db.InsertBeacon(ctx, b, allowed)
	require.NoError(t, err)
	return b
}

type PeerEntry struct {
	IA      addr.IA
	Ingress iface.ID
}

type IfInfo struct {
	IA      addr.IA
	Next    addr.IA
	Ingress iface.ID
	Egress  iface.ID
	Peers   []PeerEntry
}

func AllocBeacon(
	t *testing.T,
	ases []IfInfo,
	inIfID uint16,
	infoTS uint32,
) (beacon.Beacon, []byte) {

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
					MAC:         [path.MacLen]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
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
					MAC:         [path.MacLen]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				},
			},
			PeerEntries: peers,
		}
	}

	// XXX(roosd): deterministic beacon needed.
	pseg, err := seg.CreateSegment(time.Unix(int64(infoTS), 0), 10)
	require.NoError(t, err)

	for _, entry := range entries {
		signer := graph.NewSigner()
		// for testing purposes set the signer timestamp equal to infoTS
		signer.Timestamp = time.Unix(int64(infoTS), 0)
		err := pseg.AddASEntry(context.Background(), entry, signer)
		require.NoError(t, err)
	}
	return beacon.Beacon{Segment: pseg, InIfID: inIfID}, pseg.ID()
}
