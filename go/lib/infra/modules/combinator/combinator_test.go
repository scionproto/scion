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

package combinator

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

var (
	update = flag.Bool("update", false, "set to true to update reference testdata files")
)

func TestBadPeering(t *testing.T) {
	// Test that paths are not constructed across peering links where the IFIDs
	// on both ends do not match.
	g := graph.NewDefaultGraph()
	g.AddLink("1-ff00:0:111", 4001, "1-ff00:0:121", 4002, true)
	g.DeleteInterface(4002) // Break 4001-4002 peering, only 4001 remains in up segment
	// Break If_111_X_121_X - If_121_X_111_X peering,
	// only If_121_X_111_X remains in down segment
	g.DeleteInterface(graph.If_111_X_121_X)

	testCases := []struct {
		Name     string
		FileName string
		SrcIA    addr.IA
		DstIA    addr.IA
		Ups      []*seg.PathSegment
		Cores    []*seg.PathSegment
		Downs    []*seg.PathSegment
	}{
		{
			Name:     "broken peering",
			FileName: "00_bad_peering.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:112"),
			DstIA:    xtest.MustParseIA("1-ff00:0:122"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_110_X_111_X, graph.If_111_X_112_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_120_X_110_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_120_X_121_X, graph.If_121_X_122_X}),
			},
		},
	}

	Convey("main", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				result := Combine(tc.SrcIA, tc.DstIA, tc.Ups, tc.Cores, tc.Downs)
				txtResult := writePaths(result)
				if *update {
					err := ioutil.WriteFile(xtest.ExpandPath(tc.FileName), txtResult.Bytes(), 0644)
					xtest.FailOnErr(t, err)
				}
				expected, err := ioutil.ReadFile(xtest.ExpandPath(tc.FileName))
				xtest.FailOnErr(t, err)
				SoMsg("result", txtResult.String(), ShouldEqual, string(expected))
			})
		}
	})
}

func TestMultiPeering(t *testing.T) {
	g := graph.NewDefaultGraph()
	g.AddLink("1-ff00:0:111", 4001, "1-ff00:0:121", 4002, true)

	testCases := []struct {
		Name     string
		FileName string
		SrcIA    addr.IA
		DstIA    addr.IA
		Ups      []*seg.PathSegment
		Cores    []*seg.PathSegment
		Downs    []*seg.PathSegment
	}{
		{
			Name:     "two peerings between same ases",
			FileName: "00_multi_peering.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:112"),
			DstIA:    xtest.MustParseIA("1-ff00:0:122"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_110_X_111_X, graph.If_111_X_112_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_120_X_110_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_120_X_121_X, graph.If_121_X_122_X}),
			},
		},
	}

	Convey("main", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				result := Combine(tc.SrcIA, tc.DstIA, tc.Ups, tc.Cores, tc.Downs)
				txtResult := writePaths(result)
				if *update {
					err := ioutil.WriteFile(xtest.ExpandPath(tc.FileName), txtResult.Bytes(), 0644)
					xtest.FailOnErr(t, err)
				}
				expected, err := ioutil.ReadFile(xtest.ExpandPath(tc.FileName))
				xtest.FailOnErr(t, err)
				SoMsg("result", txtResult.String(), ShouldEqual, string(expected))
			})
		}
	})
}

func TestSameCoreParent(t *testing.T) {
	g := graph.NewDefaultGraph()
	g.AddLink("1-ff00:0:130", 4001, "1-ff00:0:111", 4002, false)

	testCases := []struct {
		Name     string
		FileName string
		SrcIA    addr.IA
		DstIA    addr.IA
		Ups      []*seg.PathSegment
		Cores    []*seg.PathSegment
		Downs    []*seg.PathSegment
	}{
		{
			Name:     "non-core ases share same core as direct upstream",
			FileName: "00_same_core_parent.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:131"),
			DstIA:    xtest.MustParseIA("1-ff00:0:112"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_131_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{4001, graph.If_111_X_112_X}),
			},
		},
	}

	Convey("main", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				result := Combine(tc.SrcIA, tc.DstIA, tc.Ups, tc.Cores, tc.Downs)
				txtResult := writePaths(result)
				if *update {
					err := ioutil.WriteFile(xtest.ExpandPath(tc.FileName), txtResult.Bytes(), 0644)
					xtest.FailOnErr(t, err)
				}
				expected, err := ioutil.ReadFile(xtest.ExpandPath(tc.FileName))
				xtest.FailOnErr(t, err)
				SoMsg("result", txtResult.String(), ShouldEqual, string(expected))
			})
		}
	})
}

func TestComputePath(t *testing.T) {
	g := graph.NewDefaultGraph()

	testCases := []struct {
		Name     string
		FileName string
		SrcIA    addr.IA
		DstIA    addr.IA
		Ups      []*seg.PathSegment
		Cores    []*seg.PathSegment
		Downs    []*seg.PathSegment
	}{
		{
			Name:     "#0 simple up-core-down",
			FileName: "00_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:131"),
			DstIA:    xtest.MustParseIA("1-ff00:0:111"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_131_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_110_X_130_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_110_X_111_X}),
			},
		},
		{
			Name:     "#1 simple up-core",
			FileName: "01_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:131"),
			DstIA:    xtest.MustParseIA("1-ff00:0:110"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_131_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_110_X_130_X}),
			},
		},
		{
			Name:     "#2 simple up only",
			FileName: "02_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:131"),
			DstIA:    xtest.MustParseIA("1-ff00:0:130"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_131_X}),
			},
		},
		{
			Name:     "#3 simple core-down",
			FileName: "03_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:130"),
			DstIA:    xtest.MustParseIA("1-ff00:0:111"),
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_110_X_130_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_110_X_111_X}),
			},
		},
		{
			Name:     "#4 simple down only",
			FileName: "04_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:110"),
			DstIA:    xtest.MustParseIA("1-ff00:0:111"),
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_110_X_111_X}),
			},
		},
		{
			Name:     "#5 inverted core",
			FileName: "05_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:131"),
			DstIA:    xtest.MustParseIA("1-ff00:0:111"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_131_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_110_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_110_X_111_X}),
			},
		},
		{
			Name:     "#6 simple long up-core-down",
			FileName: "06_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:132"),
			DstIA:    xtest.MustParseIA("2-ff00:0:212"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_131_X, graph.If_131_X_132_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_110_X, graph.If_110_X_130_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_211_X, graph.If_211_X_212_X}),
			},
		},
		{
			Name:     "#7 missing up",
			FileName: "07_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:132"),
			DstIA:    xtest.MustParseIA("1-ff00:0:122"),
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_120_X_110_X, graph.If_110_X_130_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_120_X_121_X, graph.If_121_X_122_X}),
			},
		},
		{
			Name:     "#8 missing core",
			FileName: "08_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:132"),
			DstIA:    xtest.MustParseIA("2-ff00:0:211"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_131_X, graph.If_131_X_132_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_211_X}),
			},
		},
		{
			Name:     "#9 missing down",
			FileName: "09_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:132"),
			DstIA:    xtest.MustParseIA("1-ff00:0:122"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_131_X, graph.If_131_X_132_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_120_X_110_X, graph.If_110_X_130_X}),
			},
		},
		{
			Name:     "#10 simple up-core-down, multiple cores",
			FileName: "10_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:132"),
			DstIA:    xtest.MustParseIA("1-ff00:0:112"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_131_X, graph.If_131_X_132_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_110_X_120_X, graph.If_120_X_130_X}),
				g.Beacon([]common.IFIDType{graph.If_110_X_130_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_110_X_111_X, graph.If_111_X_112_X}),
			},
		},
		{
			Name:     "#11 shortcut, destination on path, going up, vonly hf is from core",
			FileName: "11_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:133"),
			DstIA:    xtest.MustParseIA("1-ff00:0:131"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_131_X, graph.If_131_X_132_X,
					graph.If_132_X_133_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_131_X}),
			},
		},
		{
			Name:     "#12 shortcut, destination on path, going up, vonly hf is non-core",
			FileName: "12_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:133"),
			DstIA:    xtest.MustParseIA("1-ff00:0:132"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_131_X, graph.If_131_X_132_X,
					graph.If_132_X_133_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_131_X, graph.If_131_X_132_X}),
			},
		},
		{
			Name:     "#13 shortcut, destination on path, going down, verify hf is from core",
			FileName: "13_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:131"),
			DstIA:    xtest.MustParseIA("1-ff00:0:132"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_131_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_X_131_X, graph.If_131_X_132_X}),
			},
		},
		{
			Name:     "#14 shortcut, common upstream",
			FileName: "14_compute_path.txt",
			SrcIA:    xtest.MustParseIA("2-ff00:0:212"),
			DstIA:    xtest.MustParseIA("2-ff00:0:222"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_211_X, graph.If_211_X_212_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_211_X, graph.If_211_X_222_X}),
			},
		},
		{
			Name:     "#15 go through peer",
			FileName: "15_compute_path.txt",
			SrcIA:    xtest.MustParseIA("2-ff00:0:212"),
			DstIA:    xtest.MustParseIA("2-ff00:0:222"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_211_X, graph.If_211_X_212_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_220_X_210_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_220_X_221_X, graph.If_221_X_222_X}),
			},
		},
		{
			Name:     "#16 start from peer",
			FileName: "16_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:111"),
			DstIA:    xtest.MustParseIA("2-ff00:0:212"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_110_X_111_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_110_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_211_X, graph.If_211_X_212_X}),
			},
		},
		{
			Name:     "#17 start and end on peer",
			FileName: "17_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:111"),
			DstIA:    xtest.MustParseIA("2-ff00:0:211"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_110_X_111_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_110_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_211_X}),
			},
		},
		{
			Name:     "#18 only end on peer",
			FileName: "18_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:112"),
			DstIA:    xtest.MustParseIA("2-ff00:0:211"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_110_X_111_X, graph.If_111_X_112_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_110_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_211_X}),
			},
		},
		{
			Name:     "#19 don't use core shortcuts",
			FileName: "19_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:110"),
			DstIA:    xtest.MustParseIA("2-ff00:0:222"),
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_110_X}),
				g.Beacon([]common.IFIDType{graph.If_220_X_210_X, graph.If_210_X_110_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_211_X, graph.If_211_X_222_X}),
				g.Beacon([]common.IFIDType{graph.If_220_X_221_X, graph.If_221_X_222_X}),
			},
		},
		{
			Name:     "#20 core only",
			FileName: "20_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:130"),
			DstIA:    xtest.MustParseIA("2-ff00:0:210"),
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_110_X, graph.If_110_X_130_X}),
				g.Beacon([]common.IFIDType{graph.If_210_X_110_X, graph.If_110_X_120_X,
					graph.If_120_X_130_X}),
				g.Beacon([]common.IFIDType{graph.If_210_X_220_X, graph.If_220_X_120_X,
					graph.If_120_X_110_X, graph.If_110_X_130_X}),
			},
		},
	}

	Convey("main", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				result := Combine(tc.SrcIA, tc.DstIA, tc.Ups, tc.Cores, tc.Downs)
				txtResult := writePaths(result)
				if *update {
					err := ioutil.WriteFile(xtest.ExpandPath(tc.FileName), txtResult.Bytes(), 0644)
					xtest.FailOnErr(t, err)
				}
				expected, err := ioutil.ReadFile(xtest.ExpandPath(tc.FileName))
				xtest.FailOnErr(t, err)
				SoMsg("result", txtResult.String(), ShouldEqual, string(expected))
			})
		}
	})
}

func writePaths(paths []*Path) *bytes.Buffer {
	buffer := &bytes.Buffer{}
	for i, p := range paths {
		fmt.Fprintf(buffer, "Path #%d:\n", i)
		p.writeTestString(buffer)
	}
	return buffer
}
