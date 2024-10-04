// Copyright 2020 ETH Zurich
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
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
)

func TestStaticinfo(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	g := graph.NewDefaultGraph(ctrl)

	testCases := []struct {
		Name      string
		Path      []snet.PathInterface
		ASEntries []seg.ASEntry
	}{
		{
			Name: "#0 simple up-core-down",
			Path: []snet.PathInterface{
				{IA: addr.MustParseIA("1-ff00:0:131"), ID: iface.ID(graph.If_131_X_130_A)},
				{IA: addr.MustParseIA("1-ff00:0:130"), ID: iface.ID(graph.If_130_A_131_X)},
				{IA: addr.MustParseIA("1-ff00:0:130"), ID: iface.ID(graph.If_130_B_120_A)},
				{IA: addr.MustParseIA("1-ff00:0:120"), ID: iface.ID(graph.If_120_A_130_B)},
				{IA: addr.MustParseIA("1-ff00:0:120"), ID: iface.ID(graph.If_120_X_111_B)},
				{IA: addr.MustParseIA("1-ff00:0:111"), ID: iface.ID(graph.If_111_B_120_X)},
			},
			ASEntries: concatBeaconASEntries(g,
				[]uint16{graph.If_130_A_131_X},
				[]uint16{graph.If_120_A_130_B},
				[]uint16{graph.If_120_X_111_B},
			),
		},
		{
			Name: "#1 simple up-core",
			Path: []snet.PathInterface{
				{IA: addr.MustParseIA("1-ff00:0:131"), ID: iface.ID(graph.If_131_X_130_A)},
				{IA: addr.MustParseIA("1-ff00:0:130"), ID: iface.ID(graph.If_130_A_131_X)},
				{IA: addr.MustParseIA("1-ff00:0:130"), ID: iface.ID(graph.If_130_A_110_X)},
				{IA: addr.MustParseIA("1-ff00:0:110"), ID: iface.ID(graph.If_110_X_130_A)},
			},
			ASEntries: concatBeaconASEntries(g,
				[]uint16{graph.If_130_A_131_X},
				[]uint16{graph.If_110_X_130_A},
				nil,
			),
		},
		{
			Name: "#2 simple up only",
			Path: []snet.PathInterface{
				{IA: addr.MustParseIA("1-ff00:0:131"), ID: iface.ID(graph.If_131_X_130_A)},
				{IA: addr.MustParseIA("1-ff00:0:130"), ID: iface.ID(graph.If_130_A_131_X)},
			},
			ASEntries: concatBeaconASEntries(g,
				[]uint16{graph.If_130_A_131_X},
				nil,
				nil,
			),
		},
		{
			Name: "#14 shortcut, common upstream",
			Path: []snet.PathInterface{
				{IA: addr.MustParseIA("2-ff00:0:212"), ID: iface.ID(graph.If_212_X_211_A1)},
				{IA: addr.MustParseIA("2-ff00:0:211"), ID: iface.ID(graph.If_211_A1_212_X)},
				{IA: addr.MustParseIA("2-ff00:0:211"), ID: iface.ID(graph.If_211_A_222_X)},
				{IA: addr.MustParseIA("2-ff00:0:222"), ID: iface.ID(graph.If_222_X_211_A)},
			},
			ASEntries: concatBeaconASEntries(g,
				[]uint16{graph.If_210_X1_211_A, graph.If_211_A1_212_X},
				nil,
				[]uint16{graph.If_210_X1_211_A, graph.If_211_A_222_X},
			),
		},
		{
			Name: "#15 go through peer",
			Path: []snet.PathInterface{
				{IA: addr.MustParseIA("2-ff00:0:212"), ID: iface.ID(graph.If_212_X_211_A1)},
				{IA: addr.MustParseIA("2-ff00:0:211"), ID: iface.ID(graph.If_211_A1_212_X)},
				{IA: addr.MustParseIA("2-ff00:0:211"), ID: iface.ID(graph.If_211_A_221_X)},
				{IA: addr.MustParseIA("2-ff00:0:221"), ID: iface.ID(graph.If_221_X_211_A)},
				{IA: addr.MustParseIA("2-ff00:0:221"), ID: iface.ID(graph.If_221_X_222_X)},
				{IA: addr.MustParseIA("2-ff00:0:222"), ID: iface.ID(graph.If_222_X_221_X)},
			},
			ASEntries: concatBeaconASEntries(g,
				[]uint16{graph.If_210_X1_211_A, graph.If_211_A1_212_X},
				nil,
				[]uint16{graph.If_220_X_221_X, graph.If_221_X_222_X},
			),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			metadata := collectMetadata(tc.Path, tc.ASEntries)
			checkLatency(t, g, tc.Path, metadata.Latency)
			checkGeo(t, g, tc.Path, metadata.Geo)
			checkLinkType(t, g, tc.Path, metadata.LinkType)
			checkBandwidth(t, g, tc.Path, metadata.Bandwidth)
			checkInternalHops(t, g, tc.Path, metadata.InternalHops)
			checkNotes(t, g, tc.Path, metadata.Notes)
		})
	}
}

func checkLatency(t *testing.T, g *graph.Graph,
	path []snet.PathInterface, latency []time.Duration) {

	if len(path) == 0 {
		assert.Empty(t, latency)
		return
	}

	expected := []time.Duration{}
	for i := 0; i < len(path)-1; i++ {
		expected = append(expected, g.Latency(uint16(path[i].ID), uint16(path[i+1].ID)))
	}
	assert.Equal(t, expected, latency)
}

func checkBandwidth(t *testing.T, g *graph.Graph,
	path []snet.PathInterface, bandwidth []uint64) {

	if len(path) == 0 {
		assert.Empty(t, bandwidth)
		return
	}

	expected := []uint64{}
	for i := 0; i < len(path)-1; i++ {
		expected = append(expected, g.Bandwidth(uint16(path[i].ID), uint16(path[i+1].ID)))
	}
	assert.Equal(t, expected, bandwidth)
}

func checkInternalHops(t *testing.T, g *graph.Graph,
	path []snet.PathInterface, internalHops []uint32) {

	if len(path) == 0 {
		assert.Empty(t, internalHops)
		return
	}

	expected := []uint32{}
	for i := 1; i < len(path)-1; i += 2 {
		expected = append(expected, g.InternalHops(uint16(path[i].ID), uint16(path[i+1].ID)))
	}
	assert.Equal(t, expected, internalHops)
}

func checkGeo(t *testing.T, g *graph.Graph, path []snet.PathInterface, geos []snet.GeoCoordinates) {
	if len(path) == 0 {
		assert.Empty(t, geos)
		return
	}

	expected := []snet.GeoCoordinates{}
	for _, iface := range path {
		e := g.GeoCoordinates(uint16(iface.ID))
		expected = append(expected, snet.GeoCoordinates{
			Longitude: e.Longitude,
			Latitude:  e.Latitude,
			Address:   e.Address,
		})
	}
	assert.Equal(t, expected, geos)
}

func checkLinkType(t *testing.T, g *graph.Graph,
	path []snet.PathInterface, linkTypes []snet.LinkType) {

	if len(path) == 0 {
		assert.Empty(t, linkTypes)
		return
	}

	expected := []snet.LinkType{}
	for i := 0; i < len(path); i += 2 {
		expected = append(expected,
			convertLinkType(g.LinkType(uint16(path[i].ID), uint16(path[i+1].ID))),
		)
	}
	assert.Equal(t, expected, linkTypes)

}
func checkNotes(t *testing.T, g *graph.Graph, path []snet.PathInterface, notes []string) {
	if len(path) == 0 {
		assert.Empty(t, notes)
		return
	}

	// (very) explicitly gather ASes from path interface list
	ases := []addr.IA{}
	ases = append(ases, path[0].IA)
	for i := 1; i < len(path)-1; i += 2 {
		ases = append(ases, path[i].IA)
	}
	ases = append(ases, path[len(path)-1].IA)

	expected := []string{}
	for _, ia := range ases {
		expected = append(expected, fmt.Sprintf("Note %s", ia))
	}
	assert.Equal(t, expected, notes)
}

func concatBeaconASEntries(g *graph.Graph,
	upIfIDs, coreIfIDs, downIfIDs []uint16) []seg.ASEntry {

	r := []seg.ASEntry{}
	for _, ifIDs := range [][]uint16{upIfIDs, coreIfIDs, downIfIDs} {
		seg := g.BeaconWithStaticInfo(ifIDs)
		if seg != nil {
			r = append(r, seg.ASEntries...)
		}
	}
	return r
}
