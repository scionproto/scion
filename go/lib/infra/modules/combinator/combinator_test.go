// Copyright 2018 ETH Zurich
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

package combinator

import (
	"bytes"
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

func DbgPrint(segment *seg.PathSegment) {
	buffer := new(bytes.Buffer)

	for _, as := range segment.ASEntries {
		fmt.Fprintf(buffer, "%d: ", as.IA())
		for _, hop := range as.HopEntries {
			fmt.Fprintf(buffer, "(%v -> %v -> %v)", hop.RawInIA.IA(), as.IA(), hop.RawOutIA.IA())
		}
		fmt.Fprintln(buffer)
	}

	fmt.Println(buffer)
}

func TestBadPeering(t *testing.T) {
	// Test that paths are not constructed across peering links where the IFIDs
	// on both ends do not match.
	g := graph.NewDefaultGraph()
	g.AddLink("1-14", 4001, "1-15", 4002, true)
	g.DeleteInterface(4002) // Break 4001-4002 peering, only 4001 remains in up segment
	g.DeleteInterface(1415) // Break 1415-1514 peering, only 1514 remains in down segment

	testCases := []struct {
		Name  string
		SrcIA addr.IA
		DstIA addr.IA
		Ups   []*seg.PathSegment
		Cores []*seg.PathSegment
		Downs []*seg.PathSegment
		Exp   [][]PathField
	}{
		{
			Name:  "broken peering",
			SrcIA: addr.IA{I: 1, A: 17},
			DstIA: addr.IA{I: 1, A: 18},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1114, 1417}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1211}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1215, 1518}),
			},
			Exp: [][]PathField{
				{
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1714},
					{Type: HF, InIF: 1411, OutIF: 1417},
					{Type: HF, Xover: 1, OutIF: 1114},
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1112},
					{Type: HF, Xover: 1, OutIF: 1211},
					{Type: IF, ISD: 1},
					{Type: HF, OutIF: 1215},
					{Type: HF, InIF: 1512, OutIF: 1518},
					{Type: HF, InIF: 1815},
				},
			},
		},
	}

	Convey("main", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				result := Combine(tc.SrcIA, tc.DstIA, tc.Ups, tc.Cores, tc.Downs)
				SoMsg("result",
					fmt.Sprintf("%v", result),
					ShouldResemble,
					fmt.Sprintf("%v", tc.Exp),
				)
			})
		}
	})
}

func TestMultiPeering(t *testing.T) {
	g := graph.NewDefaultGraph()
	g.AddLink("1-14", 4001, "1-15", 4002, true)

	testCases := []struct {
		Name  string
		SrcIA addr.IA
		DstIA addr.IA
		Ups   []*seg.PathSegment
		Cores []*seg.PathSegment
		Downs []*seg.PathSegment
		Exp   [][]PathField
	}{
		{
			Name:  "two peerings between same ases",
			SrcIA: addr.IA{I: 1, A: 17},
			DstIA: addr.IA{I: 1, A: 18},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1114, 1417}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1211}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1215, 1518}),
			},
			Exp: [][]PathField{
				{
					{Type: IF, Shortcut: 1, Peer: 1, Up: 1, ISD: 1},
					{Type: HF, InIF: 1714},
					{Type: HF, Xover: 1, InIF: 1411, OutIF: 1417},
					{Type: HF, Xover: 1, InIF: 1415, OutIF: 1417},
					{Type: HF, Vonly: 1, OutIF: 1114},
					{Type: IF, Shortcut: 1, Peer: 1, ISD: 1},
					{Type: HF, Vonly: 1, OutIF: 1215},
					{Type: HF, Xover: 1, InIF: 1514, OutIF: 1518},
					{Type: HF, Xover: 1, InIF: 1512, OutIF: 1518},
					{Type: HF, InIF: 1815},
				},
				{
					{Type: IF, Shortcut: 1, Peer: 1, Up: 1, ISD: 1},
					{Type: HF, InIF: 1714},
					{Type: HF, Xover: 1, InIF: 1411, OutIF: 1417},
					{Type: HF, Xover: 1, InIF: 4001, OutIF: 1417},
					{Type: HF, Vonly: 1, OutIF: 1114},
					{Type: IF, Shortcut: 1, Peer: 1, ISD: 1},
					{Type: HF, Vonly: 1, OutIF: 1215},
					{Type: HF, Xover: 1, InIF: 4002, OutIF: 1518},
					{Type: HF, Xover: 1, InIF: 1512, OutIF: 1518},
					{Type: HF, InIF: 1815},
				},
				{
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1714},
					{Type: HF, InIF: 1411, OutIF: 1417},
					{Type: HF, Xover: 1, OutIF: 1114},
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1112},
					{Type: HF, Xover: 1, OutIF: 1211},
					{Type: IF, ISD: 1},
					{Type: HF, OutIF: 1215},
					{Type: HF, InIF: 1512, OutIF: 1518},
					{Type: HF, InIF: 1815},
				},
			},
		},
	}

	Convey("main", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				result := Combine(tc.SrcIA, tc.DstIA, tc.Ups, tc.Cores, tc.Downs)
				SoMsg("result",
					fmt.Sprintf("%v", result),
					ShouldResemble,
					fmt.Sprintf("%v", tc.Exp),
				)
			})
		}
	})
}

func TestComputePath(t *testing.T) {
	g := graph.NewDefaultGraph()

	testCases := []struct {
		Name  string
		SrcIA addr.IA
		DstIA addr.IA
		Ups   []*seg.PathSegment
		Cores []*seg.PathSegment
		Downs []*seg.PathSegment
		Exp   [][]PathField
	}{
		{
			Name:  "#0 simple up-core-down",
			SrcIA: addr.IA{I: 1, A: 16},
			DstIA: addr.IA{I: 1, A: 14},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1316}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1113}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1114}),
			},
			Exp: [][]PathField{
				{
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1613},
					{Type: HF, Xover: 1, OutIF: 1316},
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1311},
					{Type: HF, Xover: 1, OutIF: 1113},
					{Type: IF, ISD: 1},
					{Type: HF, OutIF: 1114},
					{Type: HF, InIF: 1411},
				},
			},
		},
		{
			Name:  "#1 simple up-core",
			SrcIA: addr.IA{I: 1, A: 16},
			DstIA: addr.IA{I: 1, A: 11},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1316}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1113}),
			},
			Downs: []*seg.PathSegment{},
			Exp: [][]PathField{
				{
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1613},
					{Type: HF, Xover: 1, OutIF: 1316},
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1311},
					{Type: HF, OutIF: 1113},
				},
			},
		},
		{
			Name:  "#2 simple up only",
			SrcIA: addr.IA{I: 1, A: 16},
			DstIA: addr.IA{I: 1, A: 13},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1316}),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{},
			Exp: [][]PathField{
				{
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1613},
					{Type: HF, OutIF: 1316},
				},
			},
		},
		{
			Name:  "#3 simple core-down",
			SrcIA: addr.IA{I: 1, A: 13},
			DstIA: addr.IA{I: 1, A: 14},
			Ups:   []*seg.PathSegment{},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1113}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1114}),
			},
			Exp: [][]PathField{
				{
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1311},
					{Type: HF, Xover: 1, OutIF: 1113},
					{Type: IF, ISD: 1},
					{Type: HF, OutIF: 1114},
					{Type: HF, InIF: 1411},
				},
			},
		},
		{
			Name:  "#4 simple down only",
			SrcIA: addr.IA{I: 1, A: 11},
			DstIA: addr.IA{I: 1, A: 14},
			Ups:   []*seg.PathSegment{},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1114}),
			},
			Exp: [][]PathField{
				{
					{Type: IF, ISD: 1},
					{Type: HF, OutIF: 1114},
					{Type: HF, InIF: 1411},
				},
			},
		},
		{
			Name:  "#5 inverted core",
			SrcIA: addr.IA{I: 1, A: 16},
			DstIA: addr.IA{I: 1, A: 14},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1316}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1311}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1114}),
			},
			Exp: [][]PathField{},
		},
		{
			Name:  "#6 simple long up-core-down",
			SrcIA: addr.IA{I: 1, A: 19},
			DstIA: addr.IA{I: 2, A: 25},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1316, 1619}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{2111, 1113}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{2123, 2325}),
			},
			Exp: [][]PathField{
				{
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1916},
					{Type: HF, InIF: 1613, OutIF: 1619},
					{Type: HF, Xover: 1, OutIF: 1316},
					{Type: IF, Up: 1, ISD: 2},
					{Type: HF, InIF: 1311},
					{Type: HF, InIF: 1121, OutIF: 1113},
					{Type: HF, Xover: 1, OutIF: 2111},
					{Type: IF, ISD: 2},
					{Type: HF, OutIF: 2123},
					{Type: HF, InIF: 2321, OutIF: 2325},
					{Type: HF, InIF: 2523},
				},
			},
		},
		{
			Name:  "#7 missing up",
			SrcIA: addr.IA{I: 1, A: 19},
			DstIA: addr.IA{I: 1, A: 18},
			Ups:   []*seg.PathSegment{},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1211, 1113}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1215, 1518}),
			},
			Exp: [][]PathField{},
		},
		{
			Name:  "#8 missing core",
			SrcIA: addr.IA{I: 1, A: 19},
			DstIA: addr.IA{I: 2, A: 23},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1316, 1619}),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{2123}),
			},
			Exp: [][]PathField{},
		},
		{
			Name:  "#9 missing down",
			SrcIA: addr.IA{I: 1, A: 19},
			DstIA: addr.IA{I: 1, A: 18},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1316, 1619}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1211, 1113}),
			},
			Downs: []*seg.PathSegment{},
			Exp:   [][]PathField{},
		},
		{
			Name:  "#10 simple up-core-down, multiple cores",
			SrcIA: addr.IA{I: 1, A: 19},
			DstIA: addr.IA{I: 1, A: 17},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1316, 1619}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1112, 1213}),
				g.Beacon([]common.IFIDType{1113}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1114, 1417}),
			},
			Exp: [][]PathField{
				{
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1916},
					{Type: HF, InIF: 1613, OutIF: 1619},
					{Type: HF, Xover: 1, OutIF: 1316},
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1311},
					{Type: HF, Xover: 1, OutIF: 1113},
					{Type: IF, ISD: 1},
					{Type: HF, OutIF: 1114},
					{Type: HF, InIF: 1411, OutIF: 1417},
					{Type: HF, InIF: 1714},
				},
				{
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1916},
					{Type: HF, InIF: 1613, OutIF: 1619},
					{Type: HF, Xover: 1, OutIF: 1316},
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1312},
					{Type: HF, InIF: 1211, OutIF: 1213},
					{Type: HF, Xover: 1, OutIF: 1112},
					{Type: IF, ISD: 1},
					{Type: HF, OutIF: 1114},
					{Type: HF, InIF: 1411, OutIF: 1417},
					{Type: HF, InIF: 1714},
				},
			},
		},
		{
			Name:  "#11 shortcut, destination on path, going up, vonly hf is from core",
			SrcIA: addr.IA{I: 1, A: 10},
			DstIA: addr.IA{I: 1, A: 16},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1316, 1619, 1910}),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1316}),
			},
			Exp: [][]PathField{
				{
					{Type: IF, Shortcut: 1, Up: 1, ISD: 1},
					{Type: HF, InIF: 1019},
					{Type: HF, InIF: 1916, OutIF: 1910},
					{Type: HF, InIF: 1613, OutIF: 1619},
					{Type: HF, Vonly: 1, OutIF: 1316},
				},
				{
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1019},
					{Type: HF, InIF: 1916, OutIF: 1910},
					{Type: HF, InIF: 1613, OutIF: 1619},
					{Type: HF, Xover: 1, OutIF: 1316},
					{Type: IF, ISD: 1},
					{Type: HF, OutIF: 1316},
					{Type: HF, InIF: 1613, OutIF: 0},
				},
			},
		},
		{
			Name:  "#12 shortcut, destination on path, going up, vonly hf is non-core",
			SrcIA: addr.IA{I: 1, A: 10},
			DstIA: addr.IA{I: 1, A: 19},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1316, 1619, 1910}),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1316, 1619}),
			},
			Exp: [][]PathField{
				{
					{Type: IF, Shortcut: 1, Up: 1, ISD: 1},
					{Type: HF, InIF: 1019},
					{Type: HF, InIF: 1916, OutIF: 1910},
					{Type: HF, Vonly: 1, InIF: 1613, OutIF: 1619},
				},
				{
					{Type: IF, Shortcut: 1, Up: 1, ISD: 1},
					{Type: HF, InIF: 1019},
					{Type: HF, InIF: 1916, OutIF: 1910},
					{Type: HF, Xover: 1, InIF: 1613, OutIF: 1619},
					{Type: HF, Vonly: 1, OutIF: 1316},
					{Type: IF, Shortcut: 1, ISD: 1},
					{Type: HF, Vonly: 1, OutIF: 1316},
					{Type: HF, InIF: 1613, OutIF: 1619},
					{Type: HF, InIF: 1916},
				},
				{
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1019},
					{Type: HF, InIF: 1916, OutIF: 1910},
					{Type: HF, InIF: 1613, OutIF: 1619},
					{Type: HF, Xover: 1, OutIF: 1316},
					{Type: IF, ISD: 1},
					{Type: HF, OutIF: 1316},
					{Type: HF, InIF: 1613, OutIF: 1619},
					{Type: HF, InIF: 1916},
				},
			},
		},
		{
			Name:  "#13 shortcut, destination on path, going down, verify hf is from core",
			SrcIA: addr.IA{I: 1, A: 16},
			DstIA: addr.IA{I: 1, A: 19},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1316}),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1316, 1619}),
			},
			Exp: [][]PathField{
				{
					{Type: IF, Shortcut: 1, ISD: 1},
					{Type: HF, Vonly: 1, InIF: 0, OutIF: 1316},
					{Type: HF, InIF: 1613, OutIF: 1619},
					{Type: HF, InIF: 1916},
				},
				{
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1613},
					{Type: HF, Xover: 1, OutIF: 1316},
					{Type: IF, ISD: 1},
					{Type: HF, OutIF: 1316},
					{Type: HF, InIF: 1613, OutIF: 1619},
					{Type: HF, InIF: 1916},
				},
			},
		},
		{
			Name:  "#14 shortcut, common upstream",
			SrcIA: addr.IA{I: 2, A: 25},
			DstIA: addr.IA{I: 2, A: 26},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{2123, 2325}),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{2123, 2326}),
			},
			Exp: [][]PathField{
				{
					{Type: IF, Shortcut: 1, Up: 1, ISD: 2},
					{Type: HF, InIF: 2523},
					{Type: HF, Xover: 1, InIF: 2321, OutIF: 2325},
					{Type: HF, Vonly: 1, OutIF: 2123},
					{Type: IF, Shortcut: 1, ISD: 2},
					{Type: HF, Vonly: 1, OutIF: 2123},
					{Type: HF, InIF: 2321, OutIF: 2326},
					{Type: HF, InIF: 2623},
				},
				{
					{Type: IF, Up: 1, ISD: 2},
					{Type: HF, InIF: 2523},
					{Type: HF, InIF: 2321, OutIF: 2325},
					{Type: HF, Xover: 1, OutIF: 2123},
					{Type: IF, ISD: 2},
					{Type: HF, OutIF: 2123},
					{Type: HF, InIF: 2321, OutIF: 2326},
					{Type: HF, InIF: 2623},
				},
			},
		},
		{
			Name:  "#15 go through peer",
			SrcIA: addr.IA{I: 2, A: 25},
			DstIA: addr.IA{I: 2, A: 26},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{2123, 2325}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{2221}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{2224, 2426}),
			},
			Exp: [][]PathField{
				{
					{Type: IF, Shortcut: 1, Peer: 1, Up: 1, ISD: 2},
					{Type: HF, InIF: 2523},
					{Type: HF, Xover: 1, InIF: 2321, OutIF: 2325},
					{Type: HF, Xover: 1, InIF: 2324, OutIF: 2325},
					{Type: HF, Vonly: 1, OutIF: 2123},
					{Type: IF, Shortcut: 1, Peer: 1, ISD: 2},
					{Type: HF, Vonly: 1, OutIF: 2224},
					{Type: HF, Xover: 1, InIF: 2423, OutIF: 2426},
					{Type: HF, Xover: 1, InIF: 2422, OutIF: 2426},
					{Type: HF, InIF: 2624},
				},
				{
					{Type: IF, Up: 1, ISD: 2},
					{Type: HF, InIF: 2523},
					{Type: HF, InIF: 2321, OutIF: 2325},
					{Type: HF, Xover: 1, OutIF: 2123},
					{Type: IF, Up: 1, ISD: 2},
					{Type: HF, InIF: 2122},
					{Type: HF, Xover: 1, OutIF: 2221},
					{Type: IF, ISD: 2},
					{Type: HF, OutIF: 2224},
					{Type: HF, InIF: 2422, OutIF: 2426},
					{Type: HF, InIF: 2624},
				},
			},
		},
		{
			Name:  "#16 start from peer",
			SrcIA: addr.IA{I: 1, A: 14},
			DstIA: addr.IA{I: 2, A: 25},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1114}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{2111}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{2123, 2325}),
			},
			Exp: [][]PathField{
				{
					{Type: IF, Shortcut: 1, Peer: 1, Up: 1, ISD: 1},
					{Type: HF, Xover: 1, InIF: 1411},
					{Type: HF, Xover: 1, InIF: 1423},
					{Type: HF, Vonly: 1, OutIF: 1114},
					{Type: IF, Shortcut: 1, Peer: 1, ISD: 2},
					{Type: HF, Vonly: 1, OutIF: 2123},
					{Type: HF, Xover: 1, InIF: 2314, OutIF: 2325},
					{Type: HF, Xover: 1, InIF: 2321, OutIF: 2325},
					{Type: HF, InIF: 2523},
				},
				{
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1411},
					{Type: HF, Xover: 1, OutIF: 1114},
					{Type: IF, Up: 1, ISD: 2},
					{Type: HF, InIF: 1121},
					{Type: HF, Xover: 1, OutIF: 2111},
					{Type: IF, ISD: 2},
					{Type: HF, OutIF: 2123},
					{Type: HF, InIF: 2321, OutIF: 2325},
					{Type: HF, InIF: 2523},
				},
			},
		},
		{
			Name:  "#17 start and end on peer",
			SrcIA: addr.IA{I: 1, A: 14},
			DstIA: addr.IA{I: 2, A: 23},
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{1114}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{2111}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{2123}),
			},
			Exp: [][]PathField{
				{
					{Type: IF, Shortcut: 1, Peer: 1, Up: 1, ISD: 1},
					{Type: HF, Xover: 1, InIF: 1411},
					{Type: HF, Xover: 1, InIF: 1423},
					{Type: HF, Vonly: 1, OutIF: 1114},
					{Type: IF, Shortcut: 1, Peer: 1, ISD: 2},
					{Type: HF, Vonly: 1, OutIF: 2123},
					{Type: HF, Xover: 1, InIF: 2314},
					{Type: HF, Xover: 1, InIF: 2321},
				},
				{
					{Type: IF, Up: 1, ISD: 1},
					{Type: HF, InIF: 1411},
					{Type: HF, Xover: 1, OutIF: 1114},
					{Type: IF, Up: 1, ISD: 2},
					{Type: HF, InIF: 1121},
					{Type: HF, Xover: 1, OutIF: 2111},
					{Type: IF, ISD: 2},
					{Type: HF, OutIF: 2123},
					{Type: HF, InIF: 2321},
				},
			},
		},
	}

	Convey("main", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				result := Combine(tc.SrcIA, tc.DstIA, tc.Ups, tc.Cores, tc.Downs)
				SoMsg("result",
					fmt.Sprintf("%v", result),
					ShouldResemble,
					fmt.Sprintf("%v", tc.Exp),
				)
			})
		}
	})
}
