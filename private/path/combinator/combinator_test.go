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

package combinator_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/path/combinator"
)

var (
	update = xtest.UpdateGoldenFiles()
)

func TestBadPeering(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	// Test that paths are not constructed across peering links where the IFIDs
	// on both ends do not match.
	g := graph.NewDefaultGraph(ctrl)
	g.AddLink("1-ff00:0:111", 4001, "1-ff00:0:121", 4002, true)
	g.DeleteInterface(4002) // Break 4001-4002 peering, only 4001 remains in up segment
	// Break If_111_X_121_X - If_121_X_111_X peering,
	// only If_121_X_111_X remains in down segment
	g.DeleteInterface(graph.If_111_C_121_X)

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
			SrcIA:    addr.MustParseIA("1-ff00:0:112"),
			DstIA:    addr.MustParseIA("1-ff00:0:122"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_B_111_A, graph.If_111_A_112_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_A_130_B}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_B_121_X, graph.If_121_X_122_X}),
			},
		},
	}
	t.Log("TestBadPeering")
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := combinator.Combine(tc.SrcIA, tc.DstIA, tc.Ups, tc.Cores, tc.Downs, false)
			txtResult := writePaths(result)
			if *update {
				err := os.WriteFile(xtest.ExpandPath(tc.FileName), txtResult.Bytes(), 0644)
				require.NoError(t, err)
			}
			expected, err := os.ReadFile(xtest.ExpandPath(tc.FileName))
			assert.NoError(t, err)
			assert.Equal(t, string(expected), txtResult.String())
		})
	}
}

func TestMiscPeering(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	g := graph.NewDefaultGraph(ctrl)
	// Add a core-core peering link. It can be used in some cases.
	g.AddLink("1-ff00:0:130", 4001, "2-ff00:0:210", 4002, true)

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
			Name:     "two peerings between same ases and core core peering",
			FileName: "00_multi_peering.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:112"),
			DstIA:    addr.MustParseIA("2-ff00:0:212"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_B_111_A, graph.If_111_A_112_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X_110_X, graph.If_110_X_130_A}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X_211_A, graph.If_211_A_212_X}),
			},
		},
		{
			// In this case, the 130-210 peering link should not be used (the router would reject)
			// because the hop through 210 would be assimilated to a valley path: one of the
			// joined segments is a core segment, not a down segment.
			Name:     "core to core peering forbidden",
			FileName: "00_core_core_invalid_peering.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:131"),
			DstIA:    addr.MustParseIA("2-ff00:0:221"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{
					graph.If_220_X_210_X, graph.If_210_X_110_X, graph.If_110_X_130_A}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_220_X_221_X}),
			},
		},
	}
	t.Log("TestMiscPeering")
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := combinator.Combine(tc.SrcIA, tc.DstIA, tc.Ups, tc.Cores, tc.Downs, false)
			txtResult := writePaths(result)
			if *update {
				err := os.WriteFile(xtest.ExpandPath(tc.FileName), txtResult.Bytes(), 0644)
				require.NoError(t, err)
			}
			expected, err := os.ReadFile(xtest.ExpandPath(tc.FileName))
			assert.NoError(t, err)
			assert.Equal(t, string(expected), txtResult.String())
		})
	}
}

func TestSameCoreParent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	g := graph.NewDefaultGraph(ctrl)

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
			SrcIA:    addr.MustParseIA("1-ff00:0:131"),
			DstIA:    addr.MustParseIA("1-ff00:0:112"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_112_X}),
			},
		},
	}
	t.Log("TestSameCoreParent")
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := combinator.Combine(tc.SrcIA, tc.DstIA, tc.Ups, tc.Cores, tc.Downs, false)
			txtResult := writePaths(result)
			if *update {
				err := os.WriteFile(xtest.ExpandPath(tc.FileName), txtResult.Bytes(), 0644)
				require.NoError(t, err)
			}
			expected, err := os.ReadFile(xtest.ExpandPath(tc.FileName))
			assert.NoError(t, err)
			assert.Equal(t, string(expected), txtResult.String())
		})
	}
}

func TestLoops(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	g := graph.NewDefaultGraph(ctrl)
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
			Name:     "core segment create a loop",
			FileName: "00_loops.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:111"),
			DstIA:    addr.MustParseIA("1-ff00:0:112"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_111_B}),
				g.Beacon([]uint16{graph.If_130_B_111_A}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_B_120_A}),
				g.Beacon([]uint16{graph.If_120_A_130_B}),
				g.Beacon([]uint16{graph.If_120_A_110_X, graph.If_110_X_130_A}),
				g.Beacon([]uint16{graph.If_130_A_110_X, graph.If_110_X_120_A}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_112_X}),
				g.Beacon([]uint16{graph.If_130_B_111_A, graph.If_111_A_112_X}),
				g.Beacon([]uint16{graph.If_120_X_111_B, graph.If_111_A_112_X}),
			},
		},
	}
	t.Log("TestLoops")
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := combinator.Combine(tc.SrcIA, tc.DstIA, tc.Ups, tc.Cores, tc.Downs, false)
			txtResult := writePaths(result)
			if *update {
				err := os.WriteFile(xtest.ExpandPath(tc.FileName), txtResult.Bytes(), 0644)
				require.NoError(t, err)
			}
			expected, err := os.ReadFile(xtest.ExpandPath(tc.FileName))
			assert.NoError(t, err)
			assert.Equal(t, string(expected), txtResult.String())
		})
	}
}

func TestComputePath(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	g := graph.NewDefaultGraph(ctrl)

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
			SrcIA:    addr.MustParseIA("1-ff00:0:131"),
			DstIA:    addr.MustParseIA("1-ff00:0:111"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_A_130_B}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_111_B}),
			},
		},
		{
			Name:     "#1 simple up-core",
			FileName: "01_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:131"),
			DstIA:    addr.MustParseIA("1-ff00:0:110"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_110_X_130_A}),
			},
		},
		{
			Name:     "#2 simple up only",
			FileName: "02_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:131"),
			DstIA:    addr.MustParseIA("1-ff00:0:130"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X}),
			},
		},
		{
			Name:     "#3 simple core-down",
			FileName: "03_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:130"),
			DstIA:    addr.MustParseIA("1-ff00:0:121"),
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_A_130_B}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_B_121_X}),
			},
		},
		{
			Name:     "#4 simple down only",
			FileName: "04_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:130"),
			DstIA:    addr.MustParseIA("1-ff00:0:111"),
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_B_111_A}),
			},
		},
		{
			Name:     "#5 inverted core",
			FileName: "05_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:131"),
			DstIA:    addr.MustParseIA("1-ff00:0:111"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_B_120_A}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_111_B}),
			},
		},
		{
			Name:     "#6 simple long up-core-down",
			FileName: "06_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:132"),
			DstIA:    addr.MustParseIA("2-ff00:0:212"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X, graph.If_131_X_132_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X_110_X, graph.If_110_X_130_A}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X_211_A, graph.If_211_A_212_X}),
			},
		},
		{
			Name:     "#7 missing up",
			FileName: "07_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:132"),
			DstIA:    addr.MustParseIA("1-ff00:0:122"),
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_A_110_X, graph.If_110_X_130_A}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_B_121_X, graph.If_121_X_122_X}),
			},
		},
		{
			Name:     "#8 missing core",
			FileName: "08_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:132"),
			DstIA:    addr.MustParseIA("2-ff00:0:211"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X, graph.If_131_X_132_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X1_211_A}),
			},
		},
		{
			Name:     "#9 missing down",
			FileName: "09_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:132"),
			DstIA:    addr.MustParseIA("1-ff00:0:122"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X, graph.If_131_X_132_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_A_130_B}),
			},
		},
		{
			Name:     "#10 simple up-core-down, multiple cores",
			FileName: "10_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:132"),
			DstIA:    addr.MustParseIA("1-ff00:0:112"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X, graph.If_131_X_132_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_A_110_X, graph.If_110_X_130_A}),
				g.Beacon([]uint16{graph.If_120_A_130_B}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_111_B, graph.If_111_A_112_X}),
			},
		},
		{
			Name:     "#11 shortcut, destination on path, going up, vonly hf is from core",
			FileName: "11_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:133"),
			DstIA:    addr.MustParseIA("1-ff00:0:131"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X, graph.If_131_X_132_X,
					graph.If_132_X_133_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X}),
			},
		},
		{
			Name:     "#12 shortcut, destination on path, going up, vonly hf is non-core",
			FileName: "12_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:133"),
			DstIA:    addr.MustParseIA("1-ff00:0:132"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X, graph.If_131_X_132_X,
					graph.If_132_X_133_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X, graph.If_131_X_132_X}),
			},
		},
		{
			Name:     "#13 shortcut, destination on path, going down, verify hf is from core",
			FileName: "13_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:131"),
			DstIA:    addr.MustParseIA("1-ff00:0:132"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X, graph.If_131_X_132_X}),
			},
		},
		{
			Name:     "#14 shortcut, common upstream",
			FileName: "14_compute_path.txt",
			SrcIA:    addr.MustParseIA("2-ff00:0:212"),
			DstIA:    addr.MustParseIA("2-ff00:0:222"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X1_211_A, graph.If_211_A1_212_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X1_211_A, graph.If_211_A_222_X}),
			},
		},
		{
			Name:     "#15 go through peer",
			FileName: "15_compute_path.txt",
			SrcIA:    addr.MustParseIA("2-ff00:0:212"),
			DstIA:    addr.MustParseIA("2-ff00:0:222"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X1_211_A, graph.If_211_A1_212_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_220_X_210_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_220_X_221_X, graph.If_221_X_222_X}),
			},
		},
		{
			Name:     "#16 start from peer",
			FileName: "16_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:131"),
			DstIA:    addr.MustParseIA("1-ff00:0:122"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_A_130_B}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_B_121_X, graph.If_121_X_122_X}),
			},
		},
		{
			Name:     "#17 start and end on peer",
			FileName: "17_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:131"),
			DstIA:    addr.MustParseIA("1-ff00:0:121"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_A_130_B}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_B_121_X}),
			},
		},
		{
			Name:     "#18 only end on peer",
			FileName: "18_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:132"),
			DstIA:    addr.MustParseIA("1-ff00:0:121"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_130_A_131_X, graph.If_131_X_132_X}),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_A_130_B}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_B_121_X}),
			},
		},
		{
			Name:     "#19 don't use core shortcuts",
			FileName: "19_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:110"),
			DstIA:    addr.MustParseIA("2-ff00:0:222"),
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X_110_X}),
				g.Beacon([]uint16{graph.If_220_X_210_X, graph.If_210_X_110_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X1_211_A, graph.If_211_A_222_X}),
				g.Beacon([]uint16{graph.If_220_X_221_X, graph.If_221_X_222_X}),
			},
		},
		{
			Name:     "#20 core only",
			FileName: "20_compute_path.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:130"),
			DstIA:    addr.MustParseIA("2-ff00:0:210"),
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X_110_X, graph.If_110_X_130_A}),
				g.Beacon([]uint16{graph.If_210_X_110_X, graph.If_110_X_120_A,
					graph.If_120_A_130_B}),
				g.Beacon([]uint16{graph.If_210_X_220_X, graph.If_220_X_120_B,
					graph.If_120_A_110_X, graph.If_110_X_130_A}),
			},
		},
	}
	t.Log("TestComputePath")
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := combinator.Combine(tc.SrcIA, tc.DstIA, tc.Ups, tc.Cores, tc.Downs, false)
			txtResult := writePaths(result)
			if *update {
				err := os.WriteFile(xtest.ExpandPath(tc.FileName), txtResult.Bytes(), 0644)
				require.NoError(t, err)
			}
			expected, err := os.ReadFile(xtest.ExpandPath(tc.FileName))
			assert.NoError(t, err)
			assert.Equal(t, string(expected), txtResult.String())
		})
	}
}
func TestFilterDuplicates(t *testing.T) {
	// Define three different path interface sequences for the test cases below.
	// These look somewhat valid, but that doesn't matter at all -- we only look
	// at the fingerprint anyway.
	path0 := []snet.PathInterface{
		{IA: addr.MustParseIA("1-ff00:0:110"), ID: iface.ID(10)},
		{IA: addr.MustParseIA("1-ff00:0:111"), ID: iface.ID(10)},
	}
	path1 := []snet.PathInterface{
		{IA: addr.MustParseIA("1-ff00:0:110"), ID: iface.ID(11)},
		{IA: addr.MustParseIA("1-ff00:0:112"), ID: iface.ID(11)},
		{IA: addr.MustParseIA("1-ff00:0:112"), ID: iface.ID(12)},
		{IA: addr.MustParseIA("1-ff00:0:111"), ID: iface.ID(12)},
	}
	path2 := []snet.PathInterface{
		{IA: addr.MustParseIA("1-ff00:0:110"), ID: iface.ID(11)},
		{IA: addr.MustParseIA("1-ff00:0:112"), ID: iface.ID(11)},
		{IA: addr.MustParseIA("1-ff00:0:112"), ID: iface.ID(22)},
		{IA: addr.MustParseIA("1-ff00:0:111"), ID: iface.ID(22)},
	}

	// Define two expiry times for the paths: paths with latest expiry will be kept
	timeEarly := time.Time{}
	timeLater := timeEarly.Add(time.Hour) // just later than timeEarly

	testPath := func(id uint32, interfaces []snet.PathInterface, expiry time.Time) combinator.Path {
		idBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(idBuf, id)
		return combinator.Path{
			// hide an id in the (otherwise unused) raw path
			SCIONPath: snetpath.SCION{Raw: idBuf},
			Metadata: snet.PathMetadata{
				Interfaces: interfaces,
				Expiry:     expiry,
			},
			Fingerprint: combinator.Fingerprint(interfaces, combinator.NewHashState()),
		}
	}

	testCases := []struct {
		Name     string
		Paths    []combinator.Path
		Expected []uint32
	}{
		{
			Name:     "nil slice",
			Paths:    nil,
			Expected: []uint32{},
		},
		{
			Name:     "empty slice",
			Paths:    []combinator.Path{},
			Expected: []uint32{},
		},
		{
			Name: "single path",
			Paths: []combinator.Path{
				testPath(1, path0, timeEarly),
			},
			Expected: []uint32{1},
		},
		{
			Name: "different paths",
			Paths: []combinator.Path{
				testPath(1, path0, timeEarly),
				testPath(2, path1, timeEarly),
			},
			Expected: []uint32{1, 2},
		},
		{
			Name: "triple",
			Paths: []combinator.Path{
				testPath(1, path0, timeEarly),
				testPath(2, path0, timeLater),
				testPath(3, path0, timeEarly),
			},
			Expected: []uint32{2},
		},
		{
			Name: "triple, same expiry",
			Paths: []combinator.Path{
				testPath(1, path0, timeEarly),
				testPath(2, path0, timeLater),
				testPath(3, path0, timeLater),
			},
			Expected: []uint32{2},
		},
		{
			Name: "triple and double",
			Paths: []combinator.Path{
				testPath(1, path0, timeEarly),
				testPath(2, path0, timeLater),
				testPath(3, path0, timeEarly),
				testPath(5, path1, timeLater),
				testPath(6, path1, timeEarly),
			},
			Expected: []uint32{2, 5},
		},
		{
			Name: "triple, double, single",
			Paths: []combinator.Path{
				testPath(1, path0, timeEarly),
				testPath(2, path0, timeLater),
				testPath(3, path0, timeEarly),
				testPath(5, path1, timeLater),
				testPath(6, path1, timeEarly),
				testPath(7, path2, timeEarly),
			},
			Expected: []uint32{2, 5, 7},
		},
		{
			Name: "triple, double, single, mixed",
			Paths: []combinator.Path{
				testPath(1, path1, timeEarly),
				testPath(2, path2, timeEarly),
				testPath(3, path0, timeEarly),
				testPath(4, path0, timeLater),
				testPath(5, path1, timeLater),
				testPath(6, path0, timeEarly),
			},
			Expected: []uint32{2, 4, 5},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {

			filtered := combinator.FilterDuplicates(tc.Paths)
			// extract IDs hidden in the raw paths:
			filteredIds := make([]uint32, len(filtered))
			for i, path := range filtered {
				filteredIds[i] = binary.LittleEndian.Uint32(path.SCIONPath.Raw)
			}
			assert.Equal(t, tc.Expected, filteredIds)
		})
	}
}

func writePaths(paths []combinator.Path) *bytes.Buffer {
	buffer := &bytes.Buffer{}
	for i, p := range paths {
		fmt.Fprintf(buffer, "Path #%d:\n", i)
		writeTestString(p, buffer)
	}
	return buffer
}

func writeTestString(p combinator.Path, w io.Writer) {
	fmt.Fprintf(w, "  Weight: %d\n", p.Weight)

	sp := scion.Decoded{}
	if err := sp.DecodeFromBytes(p.SCIONPath.Raw); err != nil {
		panic(err)
	}

	fmt.Fprintln(w, "  Fields:")
	hopIdx := 0
	for i := range sp.InfoFields {
		fmt.Fprintf(w, "    %s\n", fmtIF(sp.InfoFields[i]))
		numHops := int(sp.PathMeta.SegLen[i])
		for h := 0; h < numHops; h++ {
			fmt.Fprintf(w, "      %s\n", fmtHF(sp.HopFields[hopIdx]))
			hopIdx++
		}
	}
	fmt.Fprintln(w, "  Interfaces:")
	for _, pi := range p.Metadata.Interfaces {
		fmt.Fprintf(w, "    %v\n", pi)
	}
}

func fmtIF(field path.InfoField) string {
	return fmt.Sprintf("IF %s%s",
		flagPrint("C", field.ConsDir),
		flagPrint("P", field.Peer))
}

func fmtHF(field path.HopField) string {
	return fmt.Sprintf("HF InIF=%d OutIF=%d",
		field.ConsIngress,
		field.ConsEgress)
}

func flagPrint(name string, b bool) string {
	if b == false {
		return "."
	}
	return name
}
