// Copyright 2026 SCION Association
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
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/path/combinator"
)

// TestPeering tests peering path discovery with minimal segment sets.
func TestPeering(t *testing.T) {
	ctrl := gomock.NewController(t)
	g := graph.NewFromDescription(ctrl, graph.BigGraphDescription)

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
			Name:     "core 120 to core 410 via peering",
			FileName: "peering_120_to_410.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:120"),
			DstIA:    addr.MustParseIA("4-ff00:0:410"),
			Ups: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:120")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_310_X_410_X, graph.If_410_X_310_X}),
			},
			Downs: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:410")),
			},
		},
		{
			Name:     "core 410 to core 120 via peering",
			FileName: "peering_410_to_120.txt",
			SrcIA:    addr.MustParseIA("4-ff00:0:410"),
			DstIA:    addr.MustParseIA("1-ff00:0:120"),
			Ups: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:410")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_310_X_120_X, graph.If_120_X_310_X}),
			},
			Downs: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:120")),
			},
		},
		{
			Name:     "non-core 123 to core 410 via peering",
			FileName: "peering_123_to_410.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:123"),
			DstIA:    addr.MustParseIA("4-ff00:0:410"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_121_X, graph.If_121_X_123_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:123")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_310_X_410_X, graph.If_410_X_310_X}),
			},
			Downs: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:410")),
			},
		},
		{
			Name:     "core 410 to non-core 123 via peering",
			FileName: "peering_410_to_123.txt",
			SrcIA:    addr.MustParseIA("4-ff00:0:410"),
			DstIA:    addr.MustParseIA("1-ff00:0:123"),
			Ups: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:410")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_310_X_120_X, graph.If_120_X_310_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_121_X, graph.If_121_X_123_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:123")),
			},
		},
		{
			Name:     "non-core 122 to core 310 via peering",
			FileName: "peering_122_to_310.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:122"),
			DstIA:    addr.MustParseIA("3-ff00:0:310"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_122_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:122")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_310_X_120_X, graph.If_120_X_310_X}),
			},
			Downs: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("3-ff00:0:310")),
			},
		},
		{
			Name:     "non-core 111 to core 210 via peering",
			FileName: "peering_111_to_210.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:111"),
			DstIA:    addr.MustParseIA("2-ff00:0:210"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_110_X_111_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:111")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X_110_X, graph.If_110_X_210_X}),
			},
			Downs: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("2-ff00:0:210")),
			},
		},
		{
			Name:     "non-core 123 to non-core 411 via peering",
			FileName: "peering_123_to_411.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:123"),
			DstIA:    addr.MustParseIA("4-ff00:0:411"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_121_X, graph.If_121_X_123_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:123")),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_410_X_411_X}),
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:411")),
			},
		},
		{
			Name:     "non-core 411 to non-core 123 via peering",
			FileName: "peering_411_to_123.txt",
			SrcIA:    addr.MustParseIA("4-ff00:0:411"),
			DstIA:    addr.MustParseIA("1-ff00:0:123"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_410_X_411_X}),
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:411")),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_121_X, graph.If_121_X_123_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:123")),
			},
		},
		{
			Name:     "non-core 122 to non-core 311 via peering",
			FileName: "peering_122_to_311.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:122"),
			DstIA:    addr.MustParseIA("3-ff00:0:311"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_122_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:122")),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_310_X_311_X}),
				g.PeeringBeacon(addr.MustParseIA("3-ff00:0:311")),
			},
		},
		{
			Name:     "non-core 111 to non-core 211 via peering",
			FileName: "peering_111_to_211.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:111"),
			DstIA:    addr.MustParseIA("2-ff00:0:211"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_110_X_111_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:111")),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X_211_X}),
				g.PeeringBeacon(addr.MustParseIA("2-ff00:0:211")),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := combinator.Combine(tc.SrcIA, tc.DstIA, tc.Ups, tc.Cores, tc.Downs, false)
			txtResult := writePaths(result)
			t.Logf("Paths from %s to %s:\n%s", tc.SrcIA, tc.DstIA, txtResult.String())
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

// TestPeeringFull tests peering path discovery with complete segment sets.
// This shows all possible paths including both peering and non-peering routes,
// similar to what "scion showpaths" displays.
func TestPeeringFull(t *testing.T) {
	ctrl := gomock.NewController(t)
	g := graph.NewFromDescription(ctrl, graph.BigGraphDescription)

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
			Name:     "non-core 111 to core 210 full",
			FileName: "peering_111_to_210_full.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:111"),
			DstIA:    addr.MustParseIA("2-ff00:0:210"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_110_X_111_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:111")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X_110_X}),
			},
			Downs: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("2-ff00:0:210")),
			},
		},
		{
			Name:     "core 210 to non-core 111 full",
			FileName: "peering_210_to_111_full.txt",
			SrcIA:    addr.MustParseIA("2-ff00:0:210"),
			DstIA:    addr.MustParseIA("1-ff00:0:111"),
			Ups: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("2-ff00:0:210")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_110_X_210_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_110_X_111_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:111")),
			},
		},
		{
			Name:     "core 120 to core 410 full",
			FileName: "peering_120_to_410_full.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:120"),
			DstIA:    addr.MustParseIA("4-ff00:0:410"),
			Ups: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:120")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_410_X_310_X, graph.If_310_X_120_X}),
			},
			Downs: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:410")),
			},
		},
		{
			Name:     "core 410 to core 120 full",
			FileName: "peering_410_to_120_full.txt",
			SrcIA:    addr.MustParseIA("4-ff00:0:410"),
			DstIA:    addr.MustParseIA("1-ff00:0:120"),
			Ups: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:410")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_310_X, graph.If_310_X_410_X}),
			},
			Downs: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:120")),
			},
		},
		{
			Name:     "non-core 123 to core 410 full",
			FileName: "peering_123_to_410_full.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:123"),
			DstIA:    addr.MustParseIA("4-ff00:0:410"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_121_X, graph.If_121_X_123_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:123")),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:120")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_410_X_310_X, graph.If_310_X_120_X}),
			},
			Downs: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:410")),
			},
		},
		{
			Name:     "core 410 to non-core 123 full",
			FileName: "peering_410_to_123_full.txt",
			SrcIA:    addr.MustParseIA("4-ff00:0:410"),
			DstIA:    addr.MustParseIA("1-ff00:0:123"),
			Ups: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:410")),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:120")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_310_X, graph.If_310_X_410_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_121_X, graph.If_121_X_123_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:123")),
			},
		},
		{
			Name:     "non-core 122 to core 310 full",
			FileName: "peering_122_to_310_full.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:122"),
			DstIA:    addr.MustParseIA("3-ff00:0:310"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_122_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:122")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_310_X_120_X}),
			},
			Downs: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("3-ff00:0:310")),
			},
		},
		{
			Name:     "core 310 to non-core 122 full",
			FileName: "peering_310_to_122_full.txt",
			SrcIA:    addr.MustParseIA("3-ff00:0:310"),
			DstIA:    addr.MustParseIA("1-ff00:0:122"),
			Ups: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("3-ff00:0:310")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_310_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_122_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:122")),
			},
		},
		{
			Name:     "non-core 122 to non-core 311 full",
			FileName: "peering_122_to_311_full.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:122"),
			DstIA:    addr.MustParseIA("3-ff00:0:311"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_122_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:122")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_310_X_120_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_310_X_311_X}),
				g.PeeringBeacon(addr.MustParseIA("3-ff00:0:310")),
				g.PeeringBeacon(addr.MustParseIA("3-ff00:0:311")),
			},
		},
		{
			Name:     "non-core 311 to non-core 122 full",
			FileName: "peering_311_to_122_full.txt",
			SrcIA:    addr.MustParseIA("3-ff00:0:311"),
			DstIA:    addr.MustParseIA("1-ff00:0:122"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_310_X_311_X}),
				g.PeeringBeacon(addr.MustParseIA("3-ff00:0:311")),
				g.PeeringBeacon(addr.MustParseIA("3-ff00:0:310")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_310_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_122_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:122")),
			},
		},
		{
			Name:     "non-core 111 to non-core 211 full",
			FileName: "peering_111_to_211_full.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:111"),
			DstIA:    addr.MustParseIA("2-ff00:0:211"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_110_X_111_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:111")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X_110_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X_211_X}),
				g.PeeringBeacon(addr.MustParseIA("2-ff00:0:210")),
				g.PeeringBeacon(addr.MustParseIA("2-ff00:0:211")),
			},
		},
		{
			Name:     "non-core 211 to non-core 111 full",
			FileName: "peering_211_to_111_full.txt",
			SrcIA:    addr.MustParseIA("2-ff00:0:211"),
			DstIA:    addr.MustParseIA("1-ff00:0:111"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_210_X_211_X}),
				g.PeeringBeacon(addr.MustParseIA("2-ff00:0:211")),
				g.PeeringBeacon(addr.MustParseIA("2-ff00:0:210")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_110_X_210_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_110_X_111_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:111")),
			},
		},
		{
			Name:     "non-core 123 to non-core 411 full",
			FileName: "peering_123_to_411_full.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:123"),
			DstIA:    addr.MustParseIA("4-ff00:0:411"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_121_X, graph.If_121_X_123_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:123")),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:120")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_410_X_310_X, graph.If_310_X_120_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_410_X_411_X}),
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:410")),
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:411")),
			},
		},
		{
			Name:     "non-core 411 to non-core 123 full",
			FileName: "peering_411_to_123_full.txt",
			SrcIA:    addr.MustParseIA("4-ff00:0:411"),
			DstIA:    addr.MustParseIA("1-ff00:0:123"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_410_X_411_X}),
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:411")),
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:410")),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:120")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_310_X, graph.If_310_X_410_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_121_X, graph.If_121_X_123_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:123")),
			},
		},
		{
			Name:     "non-core 121 to non-core 122 full",
			FileName: "peering_121_to_122_full.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:121"),
			DstIA:    addr.MustParseIA("1-ff00:0:122"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_121_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:121")),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_122_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:122")),
			},
		},
		{
			Name:     "non-core 122 to non-core 121 full",
			FileName: "peering_122_to_121_full.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:122"),
			DstIA:    addr.MustParseIA("1-ff00:0:121"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_122_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:122")),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_121_X}),
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:121")),
			},
		},
		{
			Name:     "non-core 611 to non-core 621 full",
			FileName: "peering_611_to_621_full.txt",
			SrcIA:    addr.MustParseIA("6-ff00:0:611"),
			DstIA:    addr.MustParseIA("6-ff00:0:621"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_610_X_611_X}),
				g.PeeringBeacon(addr.MustParseIA("6-ff00:0:611")),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_610_X_620_X, graph.If_620_X_621_X}),
				g.PeeringBeacon(addr.MustParseIA("6-ff00:0:621")),
			},
		},
		{
			Name:     "non-core 621 to non-core 611 full",
			FileName: "peering_621_to_611_full.txt",
			SrcIA:    addr.MustParseIA("6-ff00:0:621"),
			DstIA:    addr.MustParseIA("6-ff00:0:611"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_610_X_620_X, graph.If_620_X_621_X}),
				g.PeeringBeacon(addr.MustParseIA("6-ff00:0:621")),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_610_X_611_X}),
				g.PeeringBeacon(addr.MustParseIA("6-ff00:0:611")),
			},
		},
		{
			Name:     "non-core 611 to non-core 612 full",
			FileName: "peering_611_to_612_full.txt",
			SrcIA:    addr.MustParseIA("6-ff00:0:611"),
			DstIA:    addr.MustParseIA("6-ff00:0:612"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_610_X_611_X}),
				g.PeeringBeacon(addr.MustParseIA("6-ff00:0:611")),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_610_X_612_X}),
				g.PeeringBeacon(addr.MustParseIA("6-ff00:0:612")),
			},
		},
		{
			Name:     "non-core 612 to non-core 611 full",
			FileName: "peering_612_to_611_full.txt",
			SrcIA:    addr.MustParseIA("6-ff00:0:612"),
			DstIA:    addr.MustParseIA("6-ff00:0:611"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_610_X_612_X}),
				g.PeeringBeacon(addr.MustParseIA("6-ff00:0:612")),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_610_X_611_X}),
				g.PeeringBeacon(addr.MustParseIA("6-ff00:0:611")),
			},
		},
		{
			Name:     "non-core 611 to core 620 full",
			FileName: "peering_611_to_620_full.txt",
			SrcIA:    addr.MustParseIA("6-ff00:0:611"),
			DstIA:    addr.MustParseIA("6-ff00:0:620"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_610_X_611_X}),
				g.PeeringBeacon(addr.MustParseIA("6-ff00:0:611")),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_610_X_620_X}),
				g.PeeringBeacon(addr.MustParseIA("6-ff00:0:620")),
			},
		},
		{
			Name:     "core 620 to non-core 611 full",
			FileName: "peering_620_to_611_full.txt",
			SrcIA:    addr.MustParseIA("6-ff00:0:620"),
			DstIA:    addr.MustParseIA("6-ff00:0:611"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_610_X_620_X}),
				g.PeeringBeacon(addr.MustParseIA("6-ff00:0:620")),
			},
			Cores: []*seg.PathSegment{},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_610_X_611_X}),
				g.PeeringBeacon(addr.MustParseIA("6-ff00:0:611")),
			},
		},
		{
			Name:     "non-core 411 to core 120 full",
			FileName: "peering_411_to_120_full.txt",
			SrcIA:    addr.MustParseIA("4-ff00:0:411"),
			DstIA:    addr.MustParseIA("1-ff00:0:120"),
			Ups: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_410_X_411_X}),
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:410")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_120_X_310_X, graph.If_310_X_410_X}),
			},
			Downs: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:120")),
			},
		},
		{
			Name:     "core 120 to non-core 411 full",
			FileName: "peering_120_to_411_full.txt",
			SrcIA:    addr.MustParseIA("1-ff00:0:120"),
			DstIA:    addr.MustParseIA("4-ff00:0:411"),
			Ups: []*seg.PathSegment{
				g.PeeringBeacon(addr.MustParseIA("1-ff00:0:120")),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_410_X_310_X, graph.If_310_X_120_X}),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]uint16{graph.If_410_X_411_X}),
				g.PeeringBeacon(addr.MustParseIA("4-ff00:0:410")),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result := combinator.Combine(tc.SrcIA, tc.DstIA, tc.Ups, tc.Cores, tc.Downs, false)
			txtResult := writePaths(result)
			t.Logf("Paths from %s to %s:\n%s", tc.SrcIA, tc.DstIA, txtResult.String())
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
