// Copyright 2017 ETH Zurich
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

package sqlite

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/proto"
)

var (
	ia13 = &addr.ISD_AS{I: 1, A: 13}
	ia14 = &addr.ISD_AS{I: 1, A: 14}
	ia16 = &addr.ISD_AS{I: 1, A: 16}
	ia19 = &addr.ISD_AS{I: 1, A: 19}

	ifs1 = []uint64{0, 5, 2, 3, 6, 3, 1, 0}
	ifs2 = []uint64{0, 4, 2, 3, 1, 3, 2, 0}

	hpCfgIDs = []*query.HPCfgID{
		&query.NullHpCfgID,
		{ia13, 0xdeadbeef},
	}
	types = []seg.Type{seg.UpSegment, seg.DownSegment}

	ifspecs = []query.IntfSpec{
		{IA: ia13, IfID: 5},
		{IA: ia16, IfID: 2},
		{IA: ia16, IfID: 3},
		{IA: ia16, IfID: 6},
		{IA: ia19, IfID: 1},
	}

	tables = []string{
		SegmentsTable,
		IntfToSegTable,
		StartsAtTable,
		EndsAtTable,
		SegTypesTable,
		HpCfgIdsTable,
	}
)

func allocPathSegment(ifs []uint64, expiration uint32) (*seg.PathSegment, common.RawBytes) {
	rawHops := make([][]byte, len(ifs)/2)
	for i := 0; i < len(ifs)/2; i++ {
		rawHops[i] = make([]byte, 8)
		spath.NewHopField(rawHops[i], common.IFIDType(ifs[2*i]), common.IFIDType(ifs[2*i+1]))
	}
	ases := []*seg.ASEntry{
		{
			RawIA: ia13.IAInt(),
			HopEntries: []*seg.HopEntry{
				allocHopEntry(&addr.ISD_AS{}, ia16, rawHops[0]),
			},
		},
		{
			RawIA: ia16.IAInt(),
			HopEntries: []*seg.HopEntry{
				allocHopEntry(ia13, ia19, rawHops[1]),
				allocHopEntry(ia14, ia19, rawHops[2]),
			},
		},
		{
			RawIA: ia19.IAInt(),
			HopEntries: []*seg.HopEntry{
				allocHopEntry(ia16, &addr.ISD_AS{}, rawHops[3]),
			},
		},
	}
	info := &spath.InfoField{
		TsInt: expiration,
		ISD:   1,
		Hops:  3,
	}
	pseg, _ := seg.NewSeg(info)
	for _, ase := range ases {
		if err := pseg.AddASEntry(ase, proto.SignType_none, nil); err != nil {
			fmt.Printf("Error adding ASEntry: %v", err)
		}
	}
	segID, _ := pseg.ID()
	return pseg, segID
}

func allocHopEntry(inIA, outIA *addr.ISD_AS, hopF common.RawBytes) *seg.HopEntry {
	return &seg.HopEntry{
		RawInIA:     inIA.IAInt(),
		RawOutIA:    outIA.IAInt(),
		RawHopField: hopF,
	}
}

func setupDB(t *testing.T) (*Backend, string) {
	tmpFile := tempFilename(t)
	b, err := New(tmpFile)
	if err != nil {
		t.Fatal("Failed to open DB", "err", err)
	}
	return b, tmpFile
}

func tempFilename(t *testing.T) string {
	f, err := ioutil.TempFile("", "pathdb-sqlite-")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func insertSeg(t *testing.T, b *Backend,
	pseg *seg.PathSegment, types []seg.Type, hpCfgIDs []*query.HPCfgID) int {
	inserted, err := b.InsertWithHPCfgIDs(pseg, types, hpCfgIDs)
	if err != nil {
		t.Fatal(err)
	}
	return inserted
}

func checkSegments(t *testing.T, b *Backend, segRowID int, segID common.RawBytes, ts uint32) {
	var ID int
	var rawSeg []byte
	err := b.db.QueryRow("SELECT RowID, Segment FROM Segments WHERE SegID=?",
		segID).Scan(&ID, &rawSeg)
	if err != nil {
		t.Fatal("checkSegments: Call", "err", err)
	}
	pseg, err := seg.NewSegFromRaw(common.RawBytes(rawSeg))
	if err != nil {
		t.Fatal("checkSegments: Parse", "err", err)
	}
	info, _ := pseg.InfoF()
	SoMsg("RowID match", ID, ShouldEqual, segRowID)
	SoMsg("Timestamps match", info.TsInt, ShouldEqual, ts)
}

func checkIntfToSeg(t *testing.T, b *Backend, segRowID int, intfs []query.IntfSpec) {
	for _, spec := range intfs {
		var count int
		row := b.db.QueryRow(
			"SELECT COUNT(*) FROM IntfToSeg WHERE IsdID=? AND AsID=? AND IntfID=? AND SegRowID=?",
			spec.IA.I, spec.IA.A, spec.IfID, segRowID)
		err := row.Scan(&count)
		if err != nil {
			t.Fatal("CheckIntfToSegTable", "err", err)
		}
		SoMsg(fmt.Sprintf("Has Intf %v:%v", spec.IA, spec.IfID), count, ShouldEqual, 1)
	}
	// Check that there is no interface ID 0.
	var count int
	err := b.db.QueryRow("SELECT COUNT(*) FROM IntfToSeg WHERE IntfID=0").Scan(&count)
	if err != nil {
		t.Fatal("CheckIntfToSegTable", "err", err)
	}
	SoMsg("No IF 0", count, ShouldEqual, 0)
}

func checkStartsAtOrEndsAt(t *testing.T, b *Backend, table string, segRowID int, ia *addr.ISD_AS) {
	var segID int
	queryStr := fmt.Sprintf("SELECT SegRowID FROM %s WHERE IsdID=%v AND AsID=%v", table, ia.I, ia.A)
	err := b.db.QueryRow(queryStr).Scan(&segID)
	if err != nil {
		t.Fatal("CheckStartsAtOrEndsAt", "err", err)
	}
	SoMsg("StartsAt", segID, ShouldEqual, segRowID)
}

func checkSegTypes(t *testing.T, b *Backend, segRowID int, types []seg.Type) {
	for _, segType := range types {
		var count int
		err := b.db.QueryRow("SELECT COUNT(*) FROM SegTypes WHERE SegRowID=? AND Type=?",
			segRowID, segType).Scan(&count)
		if err != nil {
			t.Fatal("checkSegTypes", "err", err)
		}
		SoMsg(fmt.Sprintf("Has type %v", segType), count, ShouldEqual, 1)
	}
}

func checkHPCfgIDs(t *testing.T, b *Backend, segRowID int, hpCfgIDs []*query.HPCfgID) {
	for _, hpCfgID := range hpCfgIDs {
		var count int
		err := b.db.QueryRow(
			"SELECT COUNT(*) FROM HPCfgIDs WHERE SegRowID=? AND IsdID=? AND AsID=? AND CfgID=?",
			segRowID, hpCfgID.IA.I, hpCfgID.IA.A, hpCfgID.ID).Scan(&count)
		if err != nil {
			t.Fatal("checkHPCfgIDs", "err", err)
		}
		SoMsg(fmt.Sprintf("Has hpCfgID %v", hpCfgID), count, ShouldEqual, 1)
	}
}

func checkInsert(t *testing.T, b *Backend, e *ExpectedInsert) {
	// Check that the Segments Table contains the segment.
	checkSegments(t, b, e.RowID, e.SegID, e.TS)
	// Check that the IntfToSegs Table contains all the interfaces.
	checkIntfToSeg(t, b, e.RowID, e.Intfs)
	// Check that the StartsAt Table contains 1-13 => 1.
	checkStartsAtOrEndsAt(t, b, StartsAtTable, e.RowID, e.StartsAt)
	// Check that the EndsAt Table contains 1-19 => 1.
	checkStartsAtOrEndsAt(t, b, EndsAtTable, e.RowID, e.EndsAt)
	// Check that SegTypes contains {0, 1} => 1
	checkSegTypes(t, b, e.RowID, e.Types)
	// Check that SegLables contains correct mappings.
	checkHPCfgIDs(t, b, e.RowID, e.HpCfgIDs)
}

type ExpectedInsert struct {
	RowID    int
	SegID    common.RawBytes
	TS       uint32
	Intfs    []query.IntfSpec
	StartsAt *addr.ISD_AS
	EndsAt   *addr.ISD_AS
	Types    []seg.Type
	HpCfgIDs []*query.HPCfgID
}

func Test_InsertWithHpCfgIDsFull(t *testing.T) {
	Convey("InsertWithHpCfgID should correctly insert a new segment", t, func() {
		b, tmpF := setupDB(t)
		defer b.db.Close()
		defer os.Remove(tmpF)
		TS := uint32(10)
		pseg, segID := allocPathSegment(ifs1, TS)
		// Call
		inserted, err := b.InsertWithHPCfgIDs(pseg, types, hpCfgIDs)
		if err != nil {
			t.Fatal(err)
		}
		// Check return value.
		SoMsg("Inserted", inserted, ShouldEqual, 1)
		// Check Insert.
		checkInsert(t, b, &ExpectedInsert{1, segID, TS, ifspecs, ia13, ia19, types, hpCfgIDs})
	})
}

func Test_UpdateExisting(t *testing.T) {
	Convey("InsertWithHpCfgID should correctly update a new segment", t, func() {
		b, tmpF := setupDB(t)
		defer b.db.Close()
		defer os.Remove(tmpF)
		oldTS := uint32(10)
		oldSeg, _ := allocPathSegment(ifs1, oldTS)
		newTS := uint32(20)
		newSeg, newSegID := allocPathSegment(ifs1, newTS)
		insertSeg(t, b, oldSeg, types[:1], hpCfgIDs[:1])
		// Call
		inserted := insertSeg(t, b, newSeg, types, hpCfgIDs)
		// Check return value.
		SoMsg("Inserted", inserted, ShouldEqual, 1)
		// Check Insert
		checkInsert(t, b,
			&ExpectedInsert{1, newSegID, newTS, ifspecs, ia13, ia19, types, hpCfgIDs})
	})
}

func Test_OlderIgnored(t *testing.T) {
	Convey("InsertWithHpCfgID should correctly ignore an older segment", t, func() {
		b, tmpF := setupDB(t)
		defer b.db.Close()
		defer os.Remove(tmpF)
		newTS := uint32(20)
		newSeg, newSegID := allocPathSegment(ifs1, newTS)
		oldTS := uint32(10)
		oldSeg, _ := allocPathSegment(ifs1, oldTS)
		insertSeg(t, b, newSeg, types, hpCfgIDs)
		// Call
		inserted := insertSeg(t, b, oldSeg, types[:1], hpCfgIDs[:1])
		// Check return value.
		SoMsg("Inserted", inserted, ShouldEqual, 0)
		// Check Insert
		checkInsert(t, b,
			&ExpectedInsert{1, newSegID, newTS, ifspecs, ia13, ia19, types, hpCfgIDs})
	})
}

func checkEmpty(t *testing.T, b *Backend, table string) {
	queryStr := fmt.Sprintf("SELECT COUNT(*) FROM %s", table)
	var count int
	err := b.db.QueryRow(queryStr).Scan(&count)
	if err != nil {
		t.Fatal("checkEmpty", "err", err)
	}
	SoMsg(fmt.Sprintf("Empty %s", table), count, ShouldEqual, 0)
}

func Test_Delete(t *testing.T) {
	Convey("Delete should correctly remove a path segment", t, func() {
		// Setup
		b, tmpF := setupDB(t)
		defer b.db.Close()
		defer os.Remove(tmpF)
		TS := uint32(10)
		pseg, segID := allocPathSegment(ifs1, TS)
		insertSeg(t, b, pseg, types, hpCfgIDs)
		// Call
		deleted, err := b.Delete(segID)
		if err != nil {
			t.Fatal(err)
		}
		// Check return value.
		SoMsg("Deleted", deleted, ShouldEqual, 1)
		// Check that all tables are empty now.
		for _, table := range tables {
			checkEmpty(t, b, table)
		}
	})
}

func Test_DeleteWithIntf(t *testing.T) {
	Convey("DeleteWithIntf should correctly remove all affected path segments", t, func() {
		// Setup
		b, tmpF := setupDB(t)
		defer b.db.Close()
		defer os.Remove(tmpF)
		TS := uint32(10)
		pseg1, _ := allocPathSegment(ifs1, TS)
		pseg2, _ := allocPathSegment(ifs2, TS)
		insertSeg(t, b, pseg1, types, hpCfgIDs)
		insertSeg(t, b, pseg2, types, hpCfgIDs)
		// Call
		deleted, err := b.DeleteWithIntf(query.IntfSpec{IA: ia16, IfID: 2})
		if err != nil {
			t.Fatal(err)
		}
		// Check return value
		SoMsg("Deleted", deleted, ShouldEqual, 2)
	})
}

func Test_GetMixed(t *testing.T) {
	Convey("Get should return the correct path segments", t, func() {
		// Setup
		b, tmpF := setupDB(t)
		defer b.db.Close()
		defer os.Remove(tmpF)
		TS := uint32(10)
		pseg1, segID1 := allocPathSegment(ifs1, TS)
		pseg2, _ := allocPathSegment(ifs2, TS)
		insertSeg(t, b, pseg1, types, hpCfgIDs)
		insertSeg(t, b, pseg2, types[:1], hpCfgIDs[:1])
		params := &query.Params{
			SegID:    segID1,
			SegTypes: []seg.Type{0},
		}
		// Call
		res, err := b.Get(params)
		if err != nil {
			t.Fatal(err)
		}
		resSegID, _ := res[0].Seg.ID()
		SoMsg("Result count", len(res), ShouldEqual, 1)
		SoMsg("SegIDs match", resSegID, ShouldResemble, segID1)
		SoMsg("HpCfgIDs match", res[0].HpCfgIDs, ShouldResemble, hpCfgIDs)
	})
}

func Test_GetAll(t *testing.T) {
	Convey("Get should return the all path segments", t, func() {
		// Setup
		b, tmpF := setupDB(t)
		defer b.db.Close()
		defer os.Remove(tmpF)
		TS := uint32(10)
		pseg1, segID1 := allocPathSegment(ifs1, TS)
		pseg2, segID2 := allocPathSegment(ifs2, TS)
		insertSeg(t, b, pseg1, types, hpCfgIDs)
		insertSeg(t, b, pseg2, types[:1], hpCfgIDs[:1])
		// Call
		res, err := b.Get(nil)
		if err != nil {
			t.Fatal(err)
		}
		SoMsg("Result count", len(res), ShouldEqual, 2)
		for _, r := range res {
			resSegID, _ := r.Seg.ID()
			if bytes.Compare(resSegID, segID1) == 0 {
				SoMsg("HpCfgIDs match", r.HpCfgIDs, ShouldResemble, hpCfgIDs)
			} else if bytes.Compare(resSegID, segID2) == 0 {
				SoMsg("HpCfgIDs match", r.HpCfgIDs, ShouldResemble, hpCfgIDs[:1])
			} else {
				t.Fatal("Unexpected result", "seg", r.Seg)
			}
		}
	})
}

func Test_GetStartsAtEndsAt(t *testing.T) {
	Convey("Get should return all path segments starting or ending at", t, func() {
		// Setup
		b, tmpF := setupDB(t)
		defer b.db.Close()
		defer os.Remove(tmpF)
		TS := uint32(10)
		pseg1, _ := allocPathSegment(ifs1, TS)
		pseg2, _ := allocPathSegment(ifs2, TS)
		insertSeg(t, b, pseg1, types, hpCfgIDs)
		insertSeg(t, b, pseg2, types[:1], hpCfgIDs[:1])
		// Call
		res, err := b.Get(&query.Params{StartsAt: []*addr.ISD_AS{ia13, ia19}})
		if err != nil {
			t.Fatal(err)
		}
		SoMsg("Result count", len(res), ShouldEqual, 2)
		res, err = b.Get(&query.Params{EndsAt: []*addr.ISD_AS{ia13, ia19}})
		if err != nil {
			t.Fatal(err)
		}
		SoMsg("Result count", len(res), ShouldEqual, 2)
	})
}

func Test_GetWithIntfs(t *testing.T) {
	Convey("Get should return all path segment with given ifIDs", t, func() {
		// Setup
		b, tmpF := setupDB(t)
		defer b.db.Close()
		defer os.Remove(tmpF)
		TS := uint32(10)
		pseg1, _ := allocPathSegment(ifs1, TS)
		pseg2, _ := allocPathSegment(ifs2, TS)
		insertSeg(t, b, pseg1, types, hpCfgIDs)
		insertSeg(t, b, pseg2, types[:1], hpCfgIDs[:1])
		params := &query.Params{
			Intfs: []*query.IntfSpec{
				{ia13, 5},
				{ia19, 2},
			},
		}
		// Call
		res, err := b.Get(params)
		if err != nil {
			t.Fatal(err)
		}
		SoMsg("Result count", len(res), ShouldEqual, 2)
	})
}

func Test_GetWithHpCfgIDs(t *testing.T) {
	Convey("Get should return all path segment with given HpCfgIDs", t, func() {
		// Setup
		b, tmpF := setupDB(t)
		defer b.db.Close()
		defer os.Remove(tmpF)
		TS := uint32(10)
		pseg1, _ := allocPathSegment(ifs1, TS)
		pseg2, _ := allocPathSegment(ifs2, TS)
		insertSeg(t, b, pseg1, types, hpCfgIDs)
		insertSeg(t, b, pseg2, types[:1], hpCfgIDs[:1])
		params := &query.Params{
			HpCfgIDs: hpCfgIDs[1:],
		}
		// Call
		res, err := b.Get(params)
		if err != nil {
			t.Fatal(err)
		}
		SoMsg("Result count", len(res), ShouldEqual, 1)
	})
}

func Test_OpenExisting(t *testing.T) {
	Convey("New should not overwrite an existing database if versions match", t, func() {
		b, tmpF := setupDB(t)
		defer os.Remove(tmpF)
		TS := uint32(10)
		pseg1, _ := allocPathSegment(ifs1, TS)
		insertSeg(t, b, pseg1, types, hpCfgIDs)
		b.db.Close()
		// Call
		b, err := New(tmpF)
		if err != nil {
			t.Fatal(err)
		}
		// Test
		// Check that path segment is still there.
		res, err := b.Get(nil)
		if err != nil {
			t.Fatal(err)
		}
		SoMsg("Segment still exists", len(res), ShouldEqual, 1)
	})
}

func Test_OpenNewer(t *testing.T) {
	Convey("New should not overwrite an existing database if it's of a newer version", t, func() {
		b, tmpF := setupDB(t)
		defer os.Remove(tmpF)
		// Write a newer version
		_, err := b.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion+1))
		if err != nil {
			t.Fatal(err)
		}
		b.db.Close()
		// Call
		b, err = New(tmpF)
		// Test
		SoMsg("Backend nil", b, ShouldBeNil)
		SoMsg("Err returned", err, ShouldNotBeNil)
	})
}
