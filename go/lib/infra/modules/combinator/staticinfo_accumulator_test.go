package combinator

import (
	"fmt"
	"math"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

func TestCollectMetadata(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	g := graph.NewDefaultGraph(ctrl)

	testCases := map[string]struct {
		FileName          string
		SrcIA             addr.IA
		DstIA             addr.IA
		Ups               []*seg.PathSegment
		Cores             []*seg.PathSegment
		Downs             []*seg.PathSegment
		expectedLatency   uint16
		expectedBW        uint32
		expectedHops      uint8
		expectedLinktypes []DenseASLinkType
		expectedGeo       []DenseGeo
		expectedNotes     []DenseNote
	}{
		"#6 simple long up-core-down": {
			FileName: "06_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:132"),
			DstIA:    xtest.MustParseIA("2-ff00:0:212"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_A_131_X,
					graph.If_131_X_132_X}, true),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_110_X,
					graph.If_110_X_130_A}, true),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X_211_A,
					graph.If_211_A_212_X}, true),
			},
			expectedLatency: uint16(graph.If_131_X_132_X) + uint16(graph.If_131_X_132_X) +
				uint16(graph.If_130_A_131_X) + uint16(graph.If_130_A_110_X) +
				uint16(graph.If_110_X_130_A) + uint16(graph.If_110_X_130_A) +
				uint16(graph.If_210_X_110_X) + uint16(graph.If_210_X_110_X) +
				uint16(graph.If_210_X_211_A) +
				uint16(graph.If_211_A_212_X) + uint16(graph.If_211_A_212_X),

			expectedBW: calcBWmin([]common.IFIDType{graph.If_131_X_132_X,
				graph.If_130_A_131_X, graph.If_130_A_110_X, graph.If_110_X_130_A,
				graph.If_210_X_110_X, graph.If_210_X_211_A, graph.If_211_A_212_X}),
			expectedHops: uint8(graph.If_131_X_132_X) +
				uint8(graph.If_130_A_110_X) +
				uint8(graph.If_110_X_130_A) +
				uint8(graph.If_210_X_110_X) +
				uint8(graph.If_211_A_212_X),
			expectedGeo: []DenseGeo{
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("1-ff00:0:132").IAInt()),
						Longitude: float32(xtest.MustParseIA("1-ff00:0:132").IAInt()),
						Address:   fmt.Sprintf("Location %s", xtest.MustParseIA("1-ff00:0:132")),
					}},
					RawIA: xtest.MustParseIA("1-ff00:0:132").IAInt(),
				},
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("1-ff00:0:131").IAInt()),
						Longitude: float32(xtest.MustParseIA("1-ff00:0:131").IAInt()),
						Address:   fmt.Sprintf("Location %s", xtest.MustParseIA("1-ff00:0:131")),
					}},
					RawIA: xtest.MustParseIA("1-ff00:0:131").IAInt(),
				},
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("1-ff00:0:130").IAInt()),
						Longitude: float32(xtest.MustParseIA("1-ff00:0:130").IAInt()),
						Address:   fmt.Sprintf("Location %s", xtest.MustParseIA("1-ff00:0:130")),
					}},
					RawIA: xtest.MustParseIA("1-ff00:0:130").IAInt(),
				},
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("1-ff00:0:110").IAInt()),
						Longitude: float32(xtest.MustParseIA("1-ff00:0:110").IAInt()),
						Address:   fmt.Sprintf("Location %s", xtest.MustParseIA("1-ff00:0:110")),
					}},
					RawIA: xtest.MustParseIA("1-ff00:0:110").IAInt(),
				},
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("2-ff00:0:210").IAInt()),
						Longitude: float32(xtest.MustParseIA("2-ff00:0:210").IAInt()),
						Address:   fmt.Sprintf("Location %s", xtest.MustParseIA("2-ff00:0:210")),
					}},
					RawIA: xtest.MustParseIA("2-ff00:0:210").IAInt(),
				},
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("2-ff00:0:211").IAInt()),
						Longitude: float32(xtest.MustParseIA("2-ff00:0:211").IAInt()),
						Address:   fmt.Sprintf("Location %s", xtest.MustParseIA("2-ff00:0:211")),
					}},
					RawIA: xtest.MustParseIA("2-ff00:0:211").IAInt(),
				},
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("2-ff00:0:212").IAInt()),
						Longitude: float32(xtest.MustParseIA("2-ff00:0:212").IAInt()),
						Address:   fmt.Sprintf("Location %s", xtest.MustParseIA("2-ff00:0:212")),
					}},
					RawIA: xtest.MustParseIA("2-ff00:0:212").IAInt(),
				},
			},
			expectedLinktypes: []DenseASLinkType{
				{
					InterLinkType: uint16(graph.If_131_X_132_X) % 3,
					RawIA:         xtest.MustParseIA("1-ff00:0:131").IAInt(),
				},
				{
					InterLinkType: uint16(graph.If_130_A_131_X) % 3,
					RawIA:         xtest.MustParseIA("1-ff00:0:130").IAInt(),
				},
				{
					InterLinkType: uint16(graph.If_110_X_130_A) % 3,
					RawIA:         xtest.MustParseIA("1-ff00:0:110").IAInt(),
				},
				{
					InterLinkType: uint16(graph.If_210_X_211_A) % 3,
					PeerLinkType:  uint16(graph.If_210_X_110_X) % 3,
					RawIA:         xtest.MustParseIA("2-ff00:0:210").IAInt(),
				},
				{
					InterLinkType: uint16(graph.If_211_A_212_X) % 3,
					RawIA:         xtest.MustParseIA("2-ff00:0:211").IAInt(),
				},
			},
			expectedNotes: []DenseNote{
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("1-ff00:0:132")),
					RawIA: xtest.MustParseIA("1-ff00:0:132").IAInt(),
				},
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("1-ff00:0:131")),
					RawIA: xtest.MustParseIA("1-ff00:0:131").IAInt(),
				},
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("1-ff00:0:130")),
					RawIA: xtest.MustParseIA("1-ff00:0:130").IAInt(),
				},
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("1-ff00:0:110")),
					RawIA: xtest.MustParseIA("1-ff00:0:110").IAInt(),
				},
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("2-ff00:0:210")),
					RawIA: xtest.MustParseIA("2-ff00:0:210").IAInt(),
				},
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("2-ff00:0:211")),
					RawIA: xtest.MustParseIA("2-ff00:0:211").IAInt(),
				},
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("2-ff00:0:212")),
					RawIA: xtest.MustParseIA("2-ff00:0:212").IAInt(),
				},
			},
		},
		"#2 simple up only": {
			FileName: "02_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:131"),
			DstIA:    xtest.MustParseIA("1-ff00:0:130"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_A_131_X}, true),
			},
			expectedLatency: uint16(graph.If_130_A_131_X),
			expectedBW:      calcBWmin([]common.IFIDType{graph.If_130_A_131_X}),
			expectedHops:    0,
			expectedGeo: []DenseGeo{
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("1-ff00:0:131").IAInt()),
						Longitude: float32(xtest.MustParseIA("1-ff00:0:131").IAInt()),
						Address:   fmt.Sprintf("Location %s", xtest.MustParseIA("1-ff00:0:131")),
					}},
					RawIA: xtest.MustParseIA("1-ff00:0:131").IAInt(),
				},
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("1-ff00:0:130").IAInt()),
						Longitude: float32(xtest.MustParseIA("1-ff00:0:130").IAInt()),
						Address:   fmt.Sprintf("Location %s", xtest.MustParseIA("1-ff00:0:130")),
					}},
					RawIA: xtest.MustParseIA("1-ff00:0:130").IAInt(),
				},
			},
			expectedLinktypes: []DenseASLinkType{
				{
					InterLinkType: uint16(graph.If_130_A_131_X) % 3,
					RawIA:         xtest.MustParseIA("1-ff00:0:130").IAInt(),
				},
			},
			expectedNotes: []DenseNote{
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("1-ff00:0:130")),
					RawIA: xtest.MustParseIA("1-ff00:0:130").IAInt(),
				},
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("1-ff00:0:131")),
					RawIA: xtest.MustParseIA("1-ff00:0:131").IAInt(),
				},
			},
		},
		"#4 simple down only": {
			FileName: "04_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:130"),
			DstIA:    xtest.MustParseIA("1-ff00:0:111"),
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_B_111_A}, true),
			},
			expectedLatency: uint16(graph.If_130_B_111_A),
			expectedBW:      calcBWmin([]common.IFIDType{graph.If_130_B_111_A}),
			expectedHops:    1,
			expectedGeo: []DenseGeo{
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("1-ff00:0:130").IAInt()),
						Longitude: float32(xtest.MustParseIA("1-ff00:0:130").IAInt()),
						Address: fmt.Sprintf("Location %s", xtest.MustParseIA("1-ff00:0:130")),
					}},
					RawIA: xtest.MustParseIA("1-ff00:0:130").IAInt(),
				},
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("1-ff00:0:111").IAInt()),
						Longitude: float32(xtest.MustParseIA("1-ff00:0:111").IAInt()),
						Address:   fmt.Sprintf("Location %s", xtest.MustParseIA("1-ff00:0:111")),
					}},
					RawIA: xtest.MustParseIA("1-ff00:0:111").IAInt(),
				},
			},
			expectedLinktypes: []DenseASLinkType{
				{
					InterLinkType: uint16(graph.If_130_B_111_A) % 3,
					RawIA:         xtest.MustParseIA("1-ff00:0:130").IAInt(),
				},
			},
			expectedNotes: []DenseNote{
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("1-ff00:0:130")),
					RawIA: xtest.MustParseIA("1-ff00:0:130").IAInt(),
				},
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("1-ff00:0:111")),
					RawIA: xtest.MustParseIA("1-ff00:0:111").IAInt(),
				},
			},
		},
		"#11 shortcut, destination on path, going up, vonly hf is from core": {
			FileName: "11_compute_path.txt",
			SrcIA:    xtest.MustParseIA("1-ff00:0:133"),
			DstIA:    xtest.MustParseIA("1-ff00:0:131"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_A_131_X, graph.If_131_X_132_X,
					graph.If_132_X_133_X}, true),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_130_A_131_X}, true),
			},
			expectedLatency: uint16(graph.If_132_X_133_X) +
				uint16(graph.If_132_X_133_X) + uint16(graph.If_131_X_132_X),
			expectedBW: calcBWmin([]common.IFIDType{graph.If_131_X_132_X,
				graph.If_132_X_133_X}),
			expectedHops: uint8(graph.If_132_X_133_X),
			expectedGeo: []DenseGeo{
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("1-ff00:0:133").IAInt()),
						Longitude: float32(xtest.MustParseIA("1-ff00:0:133").IAInt()),
						Address:    fmt.Sprintf("Location %s", xtest.MustParseIA("1-ff00:0:133")),
					}},
					RawIA: xtest.MustParseIA("1-ff00:0:133").IAInt(),
				},
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("1-ff00:0:132").IAInt()),
						Longitude: float32(xtest.MustParseIA("1-ff00:0:132").IAInt()),
						Address:    fmt.Sprintf("Location %s", xtest.MustParseIA("1-ff00:0:132")),
					}},
					RawIA: xtest.MustParseIA("1-ff00:0:132").IAInt(),
				},
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("1-ff00:0:131").IAInt()),
						Longitude: float32(xtest.MustParseIA("1-ff00:0:131").IAInt()),
						Address:    fmt.Sprintf("Location %s", xtest.MustParseIA("1-ff00:0:131")),
					}},
					RawIA: xtest.MustParseIA("1-ff00:0:131").IAInt(),
				},
			},
			expectedLinktypes: []DenseASLinkType{
				{
					InterLinkType: uint16(graph.If_132_X_133_X) % 3,
					RawIA:         xtest.MustParseIA("1-ff00:0:132").IAInt(),
				},
				{
					InterLinkType: uint16(graph.If_131_X_132_X) % 3,
					RawIA:         xtest.MustParseIA("1-ff00:0:131").IAInt(),
				},
			},
			expectedNotes: []DenseNote{
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("1-ff00:0:131")),
					RawIA: xtest.MustParseIA("1-ff00:0:131").IAInt(),
				},
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("1-ff00:0:132")),
					RawIA: xtest.MustParseIA("1-ff00:0:132").IAInt(),
				},
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("1-ff00:0:133")),
					RawIA: xtest.MustParseIA("1-ff00:0:133").IAInt(),
				},
			},
		},
		"#14 shortcut, common upstream": {
			FileName: "14_compute_path.txt",
			SrcIA:    xtest.MustParseIA("2-ff00:0:212"),
			DstIA:    xtest.MustParseIA("2-ff00:0:222"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X1_211_A,
					graph.If_211_A1_212_X}, true),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X1_211_A,
					graph.If_211_A_222_X}, true),
			},
			expectedLatency: uint16(graph.If_211_A1_212_X) +
				uint16(graph.If_211_A1_212_X) + uint16(graph.If_211_A_222_X),
			expectedBW: calcBWmin([]common.IFIDType{graph.If_211_A1_212_X,
				graph.If_211_A_222_X}),
			expectedHops: uint8(graph.If_211_A1_212_X),
			expectedGeo: []DenseGeo{
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("2-ff00:0:212").IAInt()),
						Longitude: float32(xtest.MustParseIA("2-ff00:0:212").IAInt()),
						Address:   fmt.Sprintf("Location %s", xtest.MustParseIA("2-ff00:0:212")),
					}},
					RawIA: xtest.MustParseIA("2-ff00:0:212").IAInt(),
				},
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("2-ff00:0:211").IAInt()),
						Longitude: float32(xtest.MustParseIA("2-ff00:0:211").IAInt()),
						Address:   fmt.Sprintf("Location %s", xtest.MustParseIA("2-ff00:0:211")),
					}},
					RawIA: xtest.MustParseIA("2-ff00:0:211").IAInt(),
				},
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("2-ff00:0:222").IAInt()),
						Longitude: float32(xtest.MustParseIA("2-ff00:0:222").IAInt()),
						Address:   fmt.Sprintf("Location %s", xtest.MustParseIA("2-ff00:0:222")),
					}},
					RawIA: xtest.MustParseIA("2-ff00:0:222").IAInt(),
				},
			},
			expectedLinktypes: []DenseASLinkType{
				{
					InterLinkType: uint16(graph.If_211_A_222_X) % 3,
					PeerLinkType:  uint16(graph.If_211_A1_212_X) % 3,
					RawIA:         xtest.MustParseIA("2-ff00:0:211").IAInt(),
				},
			},
			expectedNotes: []DenseNote{
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("2-ff00:0:212")),
					RawIA: xtest.MustParseIA("2-ff00:0:212").IAInt(),
				},
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("2-ff00:0:211")),
					RawIA: xtest.MustParseIA("2-ff00:0:211").IAInt(),
				},
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("2-ff00:0:222")),
					RawIA: xtest.MustParseIA("2-ff00:0:222").IAInt(),
				},
			},
		},
		"#15 go through peer": {
			FileName: "15_compute_path.txt",
			SrcIA:    xtest.MustParseIA("2-ff00:0:212"),
			DstIA:    xtest.MustParseIA("2-ff00:0:222"),
			Ups: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_210_X1_211_A,
					graph.If_211_A1_212_X}, true),
			},
			Cores: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_220_X_210_X}, true),
			},
			Downs: []*seg.PathSegment{
				g.Beacon([]common.IFIDType{graph.If_220_X_221_X,
					graph.If_221_X_222_X}, true),
			},
			expectedLatency: uint16(graph.If_211_A1_212_X) + uint16(graph.If_211_A_221_X) +
				uint16(graph.If_221_X_211_A) + uint16(graph.If_221_X_211_A) +
				uint16(graph.If_221_X_222_X),
			expectedBW: calcBWmin([]common.IFIDType{graph.If_211_A1_212_X, graph.If_211_A_221_X,
				graph.If_221_X_211_A, graph.If_221_X_222_X}),
			expectedHops: uint8(graph.If_211_A_221_X) + uint8(graph.If_221_X_211_A),
			expectedGeo: []DenseGeo{
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("2-ff00:0:212").IAInt()),
						Longitude: float32(xtest.MustParseIA("2-ff00:0:212").IAInt()),
						Address:    fmt.Sprintf("Location %s", xtest.MustParseIA("2-ff00:0:212")),
					}},
					RawIA: xtest.MustParseIA("2-ff00:0:212").IAInt(),
				},
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("2-ff00:0:211").IAInt()),
						Longitude: float32(xtest.MustParseIA("2-ff00:0:211").IAInt()),
						Address:    fmt.Sprintf("Location %s", xtest.MustParseIA("2-ff00:0:211")),
					}},
					RawIA: xtest.MustParseIA("2-ff00:0:211").IAInt(),
				},
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("2-ff00:0:221").IAInt()),
						Longitude: float32(xtest.MustParseIA("2-ff00:0:221").IAInt()),
						Address:    fmt.Sprintf("Location %s", xtest.MustParseIA("2-ff00:0:221")),
					}},
					RawIA: xtest.MustParseIA("2-ff00:0:221").IAInt(),
				},
				{
					RouterLocations: []GeoLoc{{
						Latitude:  float32(xtest.MustParseIA("2-ff00:0:222").IAInt()),
						Longitude: float32(xtest.MustParseIA("2-ff00:0:222").IAInt()),
						Address:    fmt.Sprintf("Location %s", xtest.MustParseIA("2-ff00:0:222")),
					}},
					RawIA: xtest.MustParseIA("2-ff00:0:222").IAInt(),
				},
			},
			expectedLinktypes: []DenseASLinkType{
				{
					InterLinkType: uint16(graph.If_211_A1_212_X) % 3,
					RawIA:         xtest.MustParseIA("2-ff00:0:211").IAInt(),
				},
				{
					InterLinkType: uint16(graph.If_221_X_222_X) % 3,
					PeerLinkType:  uint16(graph.If_221_X_211_A) % 3,
					RawIA:         xtest.MustParseIA("2-ff00:0:221").IAInt(),
				},
			},
			expectedNotes: []DenseNote{
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("2-ff00:0:212")),
					RawIA: xtest.MustParseIA("2-ff00:0:212").IAInt(),
				},
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("2-ff00:0:211")),
					RawIA: xtest.MustParseIA("2-ff00:0:211").IAInt(),
				},
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("2-ff00:0:221")),
					RawIA: xtest.MustParseIA("2-ff00:0:221").IAInt(),
				},
				{
					Note:  fmt.Sprintf("Note %s", xtest.MustParseIA("2-ff00:0:222")),
					RawIA: xtest.MustParseIA("2-ff00:0:222").IAInt(),
				},
			},
		},
	}

	for _, tc := range testCases {
		result := Combine(tc.SrcIA, tc.DstIA, tc.Ups, tc.Cores, tc.Downs)
		assert.Equal(t, tc.expectedLatency, result[0].StaticInfo.TotalLatency)
		assert.Equal(t, tc.expectedBW, result[0].StaticInfo.MinOfMaxBWs)
		assert.Equal(t, tc.expectedHops, result[0].StaticInfo.TotalHops)
		assert.ElementsMatch(t, tc.expectedLinktypes, result[0].StaticInfo.LinkTypes)
		assert.ElementsMatch(t, tc.expectedGeo, result[0].StaticInfo.Locations)
		assert.ElementsMatch(t, tc.expectedNotes, result[0].StaticInfo.Notes)
	}
}

func calcBWmin(ifids []common.IFIDType) uint32 {
	var BW uint32 = math.MaxUint32
	for _, val := range ifids {
		BW = uint32(math.Min(float64(BW), float64(val)))
	}
	return BW
}
