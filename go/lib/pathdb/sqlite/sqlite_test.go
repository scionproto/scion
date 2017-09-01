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

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl/seg"
	"github.com/netsec-ethz/scion/go/lib/pathdb/query"
	"github.com/netsec-ethz/scion/go/lib/spath"
)

var (
	ia13 = &addr.ISD_AS{1, 13}
	ia14 = &addr.ISD_AS{1, 14}
	ia16 = &addr.ISD_AS{1, 16}
	ia19 = &addr.ISD_AS{1, 19}

	ifs1 = []uint64{0, 5, 2, 3, 2, 6, 1, 0}
	ifs2 = []uint64{0, 4, 2, 3, 1, 8, 2, 0}

	cfgIDs = []*query.HPCfgID{
		&query.NullCfgID,
		&query.HPCfgID{ia13, 0xdeadbeef},
	}
	types = []seg.Type{0, 1}

	ifspecs = []query.IntfSpec{
		query.IntfSpec{ia13, 5},
		query.IntfSpec{ia16, 2},
		query.IntfSpec{ia16, 3},
		query.IntfSpec{ia16, 6},
		query.IntfSpec{ia19, 1},
	}

	tables = []string{
		"Segments",
		"IntfToSeg",
		"StartsAt",
		"EndsAt",
		"SegTypes",
		"HPCfgIDs",
	}
)

func allocPathSegment(ifs []uint64, expiration uint32) *seg.PathSegment {
	ases := []*seg.ASEntry{
		&seg.ASEntry{
			RawIA: ia13.Uint32(),
			HopEntries: []*seg.HopEntry{
				&seg.HopEntry{
					RawInIA:     ia13.Uint32(),
					InIF:        ifs[0],
					InMTU:       1500,
					RawOutIA:    ia16.Uint32(),
					OutIF:       ifs[1],
					RawHopField: []byte("\xde\x00\xad\x01\xbe\x02\xef\x03"),
				},
			},
		},
		&seg.ASEntry{
			RawIA: ia16.Uint32(),
			HopEntries: []*seg.HopEntry{
				&seg.HopEntry{
					RawInIA:     ia13.Uint32(),
					InIF:        ifs[2],
					InMTU:       1500,
					RawOutIA:    ia19.Uint32(),
					OutIF:       ifs[3],
					RawHopField: []byte("\xde\x00\xad\x01\xbe\x02\xef\x03"),
				},
				&seg.HopEntry{
					RawInIA:     ia13.Uint32(),
					InIF:        ifs[4],
					InMTU:       1500,
					RawOutIA:    ia14.Uint32(),
					OutIF:       ifs[5],
					RawHopField: []byte("\xde\x00\xad\x01\xbe\x02\xef\x03"),
				},
			},
		},
		&seg.ASEntry{
			RawIA: ia19.Uint32(),
			HopEntries: []*seg.HopEntry{
				&seg.HopEntry{
					RawInIA:     ia16.Uint32(),
					InIF:        ifs[6],
					InMTU:       1500,
					RawOutIA:    ia19.Uint32(),
					OutIF:       ifs[7],
					RawHopField: []byte("\xde\x00\xad\x01\xbe\x02\xef\x03"),
				},
			},
		},
	}
	info := spath.InfoField{
		TsInt: expiration,
		ISD:   1,
		Hops:  3,
	}
	rawInfo := make(common.RawBytes, 8)
	info.Write(rawInfo)
	return &seg.PathSegment{
		RawInfo:   rawInfo,
		ASEntries: ases,
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
	pseg *seg.PathSegment, types []seg.Type, cfgIDs []*query.HPCfgID) int {
	inserted, cerr := b.InsertWithCfgIDs(pseg, types, cfgIDs)
	if cerr != nil {
		t.Fatal(cerr)
	}
	return inserted
}

func checkSegments(t *testing.T, b *Backend, rowID int, segID common.RawBytes, ts uint32) {
	var ID int
	var rawSeg []byte
	err := b.db.QueryRow("SELECT ID, Segment FROM Segments WHERE SegID=?", segID).Scan(&ID, &rawSeg)
	if err != nil {
		t.Fatal("checkSegments: Call", "err", err)
	}
	pseg, cerr := seg.NewFromRaw(common.RawBytes(rawSeg))
	if cerr != nil {
		t.Fatal("checkSegments: Parse", "err", cerr)
	}
	info, _ := pseg.Info()
	SoMsg("RowID match", ID, ShouldEqual, rowID)
	SoMsg("Timestamps match", info.TsInt, ShouldEqual, ts)
}

func checkIntfToSeg(t *testing.T, b *Backend, rowID int, intfs []query.IntfSpec) {
	for _, spec := range intfs {
		var count int
		row := b.db.QueryRow(
			"SELECT COUNT(*) FROM IntfToSeg WHERE IsdID=? AND AsID=? AND IntfID=? AND SegID=?",
			spec.IA.I, spec.IA.A, spec.IfID, rowID)
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

func checkStartsAtOrEndsAt(t *testing.T, b *Backend, table string, rowID int, ia *addr.ISD_AS) {
	var segID int
	queryStr := fmt.Sprintf("SELECT SegID FROM %s WHERE IsdID=%v AND AsID=%v", table, ia.I, ia.A)
	err := b.db.QueryRow(queryStr).Scan(&segID)
	if err != nil {
		t.Fatal("CheckStartsAtOrEndsAt", "err", err)
	}
	SoMsg("StartsAt", segID, ShouldEqual, rowID)
}

func checkSegTypes(t *testing.T, b *Backend, rowID int, types []seg.Type) {
	for _, segType := range types {
		var count int
		err := b.db.QueryRow("SELECT COUNT(*) FROM SegTypes WHERE SegID=? AND Type=?",
			rowID, segType).Scan(&count)
		if err != nil {
			t.Fatal("checkSegTypes", "err", err)
		}
		SoMsg(fmt.Sprintf("Has type %v", segType), count, ShouldEqual, 1)
	}
}

func checkHPCfgIDs(t *testing.T, b *Backend, rowID int, cfgIDs []*query.HPCfgID) {
	for _, cfgID := range cfgIDs {
		var count int
		err := b.db.QueryRow(
			"SELECT COUNT(*) FROM HPCfgIDs WHERE SegID=? AND IsdID=? AND AsID=? AND CfgID=?",
			rowID, cfgID.IA.I, cfgID.IA.A, cfgID.ID).Scan(&count)
		if err != nil {
			t.Fatal("checkHPCfgIDs", "err", err)
		}
		SoMsg(fmt.Sprintf("Has cfgID %v", cfgID), count, ShouldEqual, 1)
	}
}

func checkInsert(t *testing.T, b *Backend, e *ExpectedInsert) {
	// Check that the Segments Table contains the segment.
	checkSegments(t, b, e.RowID, e.SegID, e.TS)
	// Check that the IntfToSegs Table contains all the interfaces.
	checkIntfToSeg(t, b, e.RowID, e.Intfs)
	// Check that the StartsAt Table contains 1-13 => 1.
	checkStartsAtOrEndsAt(t, b, "StartsAt", e.RowID, e.StartsAt)
	// Check that the EndsAt Table contains 1-19 => 1.
	checkStartsAtOrEndsAt(t, b, "EndsAt", e.RowID, e.EndsAt)
	// Check that SegTypes contains {0, 1} => 1
	checkSegTypes(t, b, e.RowID, e.Types)
	// Check that SegLables contains correct mappings.
	checkHPCfgIDs(t, b, e.RowID, e.CfgIDs)
}

type ExpectedInsert struct {
	RowID    int
	SegID    common.RawBytes
	TS       uint32
	Intfs    []query.IntfSpec
	StartsAt *addr.ISD_AS
	EndsAt   *addr.ISD_AS
	Types    []seg.Type
	CfgIDs   []*query.HPCfgID
}

func Test_InsertWithCfgIDsFull(t *testing.T) {
	Convey("InsertWithCfgID should correctly insert a new segment", t, func() {
		b, tmpF := setupDB(t)
		TS := uint32(10)
		pseg := allocPathSegment(ifs1, TS)
		// Call
		inserted, err := b.InsertWithCfgIDs(pseg, types, cfgIDs)
		if err != nil {
			t.Fatal(err)
		}
		// Check return value.
		SoMsg("Inserted", inserted, ShouldEqual, 1)
		// Check Insert.
		checkInsert(t, b, &ExpectedInsert{1, pseg.ID(), TS, ifspecs, ia13, ia19, types, cfgIDs})
		os.Remove(tmpF)
	})
}

func Test_UpdateExisting(t *testing.T) {
	Convey("InsertWithCfgID should correctly update a new segment", t, func() {
		b, tmpF := setupDB(t)
		oldTS := uint32(10)
		oldSeg := allocPathSegment(ifs1, oldTS)
		newTS := uint32(20)
		newSeg := allocPathSegment(ifs1, newTS)
		insertSeg(t, b, oldSeg, types[:1], cfgIDs[:1])
		// Call
		inserted := insertSeg(t, b, newSeg, types, cfgIDs)
		// Check return value.
		SoMsg("Inserted", inserted, ShouldEqual, 1)
		// Check Insert
		checkInsert(t, b,
			&ExpectedInsert{1, newSeg.ID(), newTS, ifspecs, ia13, ia19, types, cfgIDs})
		os.Remove(tmpF)
	})
}

func Test_OlderIgnored(t *testing.T) {
	Convey("InsertWithCfgID should correctly ignore an older segment", t, func() {
		b, tmpF := setupDB(t)
		newTS := uint32(20)
		newSeg := allocPathSegment(ifs1, newTS)
		oldTS := uint32(10)
		oldSeg := allocPathSegment(ifs1, oldTS)
		insertSeg(t, b, newSeg, types, cfgIDs)
		// Call
		inserted := insertSeg(t, b, oldSeg, types[:1], cfgIDs[:1])
		// Check return value.
		SoMsg("Inserted", inserted, ShouldEqual, 0)
		// Check Insert
		checkInsert(t, b,
			&ExpectedInsert{1, newSeg.ID(), newTS, ifspecs, ia13, ia19, types, cfgIDs})
		os.Remove(tmpF)
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
		b, tmpF := setupDB(t)
		// Setup
		TS := uint32(10)
		pseg := allocPathSegment(ifs1, TS)
		insertSeg(t, b, pseg, types, cfgIDs)
		// Call
		deleted, cerr := b.Delete(pseg.ID())
		if cerr != nil {
			t.Fatal(cerr)
		}
		// Check return value.
		SoMsg("Deleted", deleted, ShouldEqual, 1)
		// Check that all tables are empty now.
		for _, table := range tables {
			checkEmpty(t, b, table)
		}
		b.close()
		os.Remove(tmpF)
	})
}

func Test_DeleteWithIntf(t *testing.T) {
	Convey("DeleteWithIntf should correctly remove all affected path segments", t, func() {
		// Setup
		b, tmpF := setupDB(t)
		TS := uint32(10)
		pseg1 := allocPathSegment(ifs1, TS)
		pseg2 := allocPathSegment(ifs2, TS)
		insertSeg(t, b, pseg1, types, cfgIDs)
		insertSeg(t, b, pseg2, types, cfgIDs)
		// Call
		deleted, cerr := b.DeleteWithIntf(query.IntfSpec{ia16, 2})
		if cerr != nil {
			t.Fatal(cerr)
		}
		// Check return value
		SoMsg("Deleted", deleted, ShouldEqual, 2)
		b.close()
		os.Remove(tmpF)
	})
}

func Test_GetMixed(t *testing.T) {
	Convey("Get should return the correct path segments", t, func() {
		// Setup
		b, tmpF := setupDB(t)
		TS := uint32(10)
		pseg1 := allocPathSegment(ifs1, TS)
		pseg2 := allocPathSegment(ifs2, TS)
		insertSeg(t, b, pseg1, types, cfgIDs)
		insertSeg(t, b, pseg2, types[:1], cfgIDs[:1])
		params := &query.Params{
			SegID:    pseg1.ID(),
			SegTypes: []seg.Type{0},
		}
		// Call
		res, cerr := b.Get(params)
		if cerr != nil {
			t.Fatal(cerr)
		}
		SoMsg("Result count", len(res), ShouldEqual, 1)
		SoMsg("SegIDs match", res[0].Seg.ID(), ShouldResemble, pseg1.ID())
		SoMsg("CfgIDs match", res[0].CfgIDs, ShouldResemble, cfgIDs)
		b.close()
		os.Remove(tmpF)
	})
}

func Test_GetAll(t *testing.T) {
	Convey("Get should return the all path segments", t, func() {
		// Setup
		b, tmpF := setupDB(t)
		TS := uint32(10)
		pseg1 := allocPathSegment(ifs1, TS)
		pseg2 := allocPathSegment(ifs2, TS)
		insertSeg(t, b, pseg1, types, cfgIDs)
		insertSeg(t, b, pseg2, types[:1], cfgIDs[:1])
		// Call
		res, cerr := b.Get(nil)
		if cerr != nil {
			t.Fatal(cerr)
		}
		SoMsg("Result count", len(res), ShouldEqual, 2)
		for _, r := range res {
			if bytes.Compare(r.Seg.ID(), pseg1.ID()) == 0 {
				SoMsg("CfgIDs match", r.CfgIDs, ShouldResemble, cfgIDs)
			} else if bytes.Compare(r.Seg.ID(), pseg2.ID()) == 0 {
				SoMsg("CfgIDs match", r.CfgIDs, ShouldResemble, cfgIDs[:1])
			} else {
				t.Fatal("Unexpected result", "seg", r.Seg)
			}
		}
		b.close()
		os.Remove(tmpF)
	})
}

func Test_GetStartsAtEndsAt(t *testing.T) {
	Convey("Get should return all path segments starting or ending at", t, func() {
		// Setup
		b, tmpF := setupDB(t)
		TS := uint32(10)
		pseg1 := allocPathSegment(ifs1, TS)
		pseg2 := allocPathSegment(ifs2, TS)
		insertSeg(t, b, pseg1, types, cfgIDs)
		insertSeg(t, b, pseg2, types[:1], cfgIDs[:1])
		// Call
		res, cerr := b.Get(&query.Params{StartsAt: []*addr.ISD_AS{ia13, ia19}})
		if cerr != nil {
			t.Fatal(cerr)
		}
		SoMsg("Result count", len(res), ShouldEqual, 2)
		res, cerr = b.Get(&query.Params{EndsAt: []*addr.ISD_AS{ia13, ia19}})
		if cerr != nil {
			t.Fatal(cerr)
		}
		SoMsg("Result count", len(res), ShouldEqual, 2)
		b.close()
		os.Remove(tmpF)
	})
}

func Test_GetWithIntfs(t *testing.T) {
	Convey("Get should return all path segment with given ifIDs", t, func() {
		// Setup
		b, tmpF := setupDB(t)
		TS := uint32(10)
		pseg1 := allocPathSegment(ifs1, TS)
		pseg2 := allocPathSegment(ifs2, TS)
		insertSeg(t, b, pseg1, types, cfgIDs)
		insertSeg(t, b, pseg2, types[:1], cfgIDs[:1])
		params := &query.Params{
			Intfs: []*query.IntfSpec{
				&query.IntfSpec{ia13, 5},
				&query.IntfSpec{ia19, 2},
			},
		}
		// Call
		res, cerr := b.Get(params)
		if cerr != nil {
			t.Fatal(cerr)
		}
		SoMsg("Result count", len(res), ShouldEqual, 2)
		b.close()
		os.Remove(tmpF)
	})
}

func Test_GetWithCfgIDs(t *testing.T) {
	Convey("Get should return all path segment with given CfgIDs", t, func() {
		// Setup
		b, tmpF := setupDB(t)
		TS := uint32(10)
		pseg1 := allocPathSegment(ifs1, TS)
		pseg2 := allocPathSegment(ifs2, TS)
		insertSeg(t, b, pseg1, types, cfgIDs)
		insertSeg(t, b, pseg2, types[:1], cfgIDs[:1])
		params := &query.Params{
			CfgIDs: cfgIDs[1:],
		}
		// Call
		res, cerr := b.Get(params)
		if cerr != nil {
			t.Fatal(cerr)
		}
		SoMsg("Result count", len(res), ShouldEqual, 1)
		b.close()
		os.Remove(tmpF)
	})
}

func Test_OpenExisting(t *testing.T) {
	Convey("New should not overwrite an existing database if versions match", t, func() {
		b, tmpF := setupDB(t)
		TS := uint32(10)
		pseg1 := allocPathSegment(ifs1, TS)
		insertSeg(t, b, pseg1, types, cfgIDs)
		b.close()
		// Call
		b, cerr := New(tmpF)
		if cerr != nil {
			t.Fatal(cerr)
		}
		// Test
		// Check that path segment is still there.
		res, cerr := b.Get(nil)
		if cerr != nil {
			t.Fatal(cerr)
		}
		SoMsg("Segment still exists", len(res), ShouldEqual, 1)
		b.close()
		os.Remove(tmpF)
	})
}

func Test_OpenNewer(t *testing.T) {
	Convey("New should not overwrite an existing database if it's of a newer version", t, func() {
		b, tmpF := setupDB(t)
		// Write a newer version
		_, err := b.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion+1))
		if err != nil {
			t.Fatal(err)
		}
		b.close()
		// Call
		b, cerr := New(tmpF)
		// Test
		SoMsg("Backend nil", b, ShouldBeNil)
		SoMsg("Err returned", cerr, ShouldNotBeNil)
		os.Remove(tmpF)
	})
}
