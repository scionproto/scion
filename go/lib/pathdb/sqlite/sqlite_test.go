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
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/netsec-ethz/scion/go/lib/pathdb/query"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl/seg"
	"github.com/netsec-ethz/scion/go/lib/spath"

	. "github.com/smartystreets/goconvey/convey"
)

var (
	ia13 = &addr.ISD_AS{1, 13}
	ia14 = &addr.ISD_AS{1, 14}
	ia16 = &addr.ISD_AS{1, 16}
	ia19 = &addr.ISD_AS{1, 19}

	ifspecs = []query.IntfSpec{
		query.IntfSpec{ia13, 5},
		query.IntfSpec{ia16, 2},
		query.IntfSpec{ia16, 3},
		query.IntfSpec{ia16, 6},
		query.IntfSpec{ia19, 1},
	}
)

func allocPathSegment(expiration uint32) *seg.PathSegment {
	ases := []*seg.ASEntry{
		&seg.ASEntry{
			RawIA: ia13.Uint32(),
			HopEntries: []*seg.HopEntry{
				&seg.HopEntry{
					RawInIA:     ia13.Uint32(),
					InIF:        0,
					InMTU:       1500,
					RawOutIA:    ia16.Uint32(),
					OutIF:       5,
					RawHopField: []byte("\xde\xad\xbe\xef"),
				},
			},
		},
		&seg.ASEntry{
			RawIA: ia16.Uint32(),
			HopEntries: []*seg.HopEntry{
				&seg.HopEntry{
					RawInIA:     ia13.Uint32(),
					InIF:        2,
					InMTU:       1500,
					RawOutIA:    ia19.Uint32(),
					OutIF:       3,
					RawHopField: []byte("\xde\xad\xbe\xef"),
				},
				&seg.HopEntry{
					RawInIA:     ia13.Uint32(),
					InIF:        2,
					InMTU:       1500,
					RawOutIA:    ia14.Uint32(),
					OutIF:       6,
					RawHopField: []byte("\xde\xad\xbe\xef"),
				},
			},
		},
		&seg.ASEntry{
			RawIA: ia19.Uint32(),
			HopEntries: []*seg.HopEntry{
				&seg.HopEntry{
					RawInIA:     ia16.Uint32(),
					InIF:        1,
					InMTU:       1500,
					RawOutIA:    ia19.Uint32(),
					OutIF:       0,
					RawHopField: []byte("\xde\xad\xbe\xef"),
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

func TempFilename(t *testing.T) string {
	f, err := ioutil.TempFile("", "pathdb-sqlite-")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func checkSegments(t *testing.T, b *Backend, rowID int, segID common.RawBytes, ts int) {
	var ID int
	var rawSeg []byte
	err := b.db.QueryRow("SELECT ID, Segment FROM Segments WHERE SegID=?", segID).Scan(&ID, &rawSeg)
	if err != nil {
		t.Fatal("checkSegments: Call", "err", err)
	}
	pseg, err := seg.NewPathSegmentFromRaw(common.RawBytes(rawSeg))
	if err != nil {
		t.Fatal("checkSegments: Parse", "err", err)
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

func checkSegTypes(t *testing.T, b *Backend, rowID int, types []uint8) {
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

func checkSegLabels(t *testing.T, b *Backend, rowID int, labels []query.SegLabel) {
	for _, label := range labels {
		var count int
		err := b.db.QueryRow("SELECT COUNT(*) FROM SegLabels WHERE SegID=? AND Label=?",
			rowID, label).Scan(&count)
		if err != nil {
			t.Fatal("checkSegLabels", "err", err)
		}
		SoMsg(fmt.Sprintf("Has label %v", label), count, ShouldEqual, 1)
	}
}

func Test_InsertWithLabelsFull(t *testing.T) {
	Convey("InsertWithLabel should correctly insert a new segment", t, func() {
		tmpFile := TempFilename(t)
		//defer os.Remove(tmpFile)
		b, err := New(tmpFile)
		if err != nil {
			t.Fatal("Failed to open DB", "err", err)
		}
		pseg := allocPathSegment(1)
		labels := []query.SegLabel{query.NullLabel, query.SegLabel([]byte("\xde\xad\xbe\xef"))}
		types := []uint8{0, 1}
		// Call
		inserted, err := b.InsertWithLabels(pseg, types, labels)
		if err != nil {
			t.Fatal(err)
		}
		// Check return value.
		SoMsg("Inserted", inserted, ShouldEqual, 1)
		// Check that the Segments Table contains the segment.
		checkSegments(t, b, 1, pseg.ID(), 1)
		// Check that the IntfToSegs Table contains all the interfaces.
		checkIntfToSeg(t, b, 1, ifspecs)
		// Check that the StartsAt Table contains 1-13 => 1.
		checkStartsAtOrEndsAt(t, b, "StartsAt", 1, ia13)
		// Check that the EndsAt Table contains 1-19 => 1.
		checkStartsAtOrEndsAt(t, b, "EndsAt", 1, ia19)
		// Check that SegTypes contains {0, 1} => 1
		checkSegTypes(t, b, 1, types)
		// Check that SegLables contains correct mappings.
		checkSegLabels(t, b, 1, labels)
	})
}

func Test_UpdateExisting(t *testing.T) {
	tmpFile := TempFilename(t)
	defer os.Remove(tmpFile)
	b, err := New(tmpFile)
	if err != nil {
		t.Fatal("Failed to open DB", "err", err)
	}
	oldSeg := allocPathSegment(1)
	oldLabels := []query.SegLabel{query.NullLabel}
	oldTypes := []uint8{0}
	_, err = b.InsertWithLabels(oldSeg, oldTypes, oldLabels)
	if err != nil {
		t.Fatal(err)
	}
	newSeg := allocPathSegment(2)
	newLabels := []query.SegLabel{query.NullLabel, query.SegLabel([]byte("\xde\xad\xbe\xef"))}
	newTypes := []uint8{0, 1}
	// Call
	inserted, err := b.InsertWithLabels(newSeg, newTypes, newLabels)
	if err != nil {
		t.Fatal(err)
	}
	// Check return value.
	SoMsg("Inserted", inserted, ShouldEqual, 1)
	// Check that the Segments Table contains the new segment.
	checkSegments(t, b, 1, newSeg.ID(), 2)
}
