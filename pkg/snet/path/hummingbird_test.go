// Copyright 2026 ETH Zurich
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

package path_test

import (
	"context"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/private/util"
	dppath "github.com/scionproto/scion/pkg/slayers/path"
	dphumm "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/stretchr/testify/require"
)

func TestNewWithNow(t *testing.T) {
	const referenceEpochTime uint32 = 123456
	r, err := path.NewReservation(path.WithNow(util.SecsToTime(referenceEpochTime)),
		path.WithDstIA(addr.MustParseIA("1-ff00:0:112")))
	require.NoError(t, err)
	require.Equal(t, referenceEpochTime, util.TimeToSecs(r.Now))
}

func TestNewWithMinBW(t *testing.T) {
	const referenceBw uint16 = 42
	r, err := path.NewReservation(path.WithMinBW(referenceBw),
		path.WithDstIA(addr.MustParseIA("1-ff00:0:112")))
	require.NoError(t, err)
	require.Equal(t, referenceBw, r.MinBW)
}

func TestSetFlyover(t *testing.T) {
	const referenceEpochTime uint32 = 123456
	referenceTime := util.SecsToTime(referenceEpochTime)
	r := path.Reservation{
		DstIA: addr.MustParseIA("1-ff00:0:112"),
		Dec:   createHummingbirdPath(referenceTime),
		Now:   referenceTime,
		MinBW: 1,
	}
	r.Hops = make([]*path.FlyoverData, len(r.Dec.HopFields))
	// There are 4 hops in the path:
	require.Equal(t, 4, len(r.Hops))

	// Mock a flyover in AS 110 between ingress 1 and egress 2.
	flyoverData := path.FlyoverData{
		BaseHop: path.BaseHop{
			IA:      addr.MustParseIA("1-ff00:0:110"),
			Ingress: 1,
			Egress:  2,
		},
		IsFlyover: true,
		ResID:     1,
		Bw:        1,
		StartTime: referenceEpochTime,
		Duration:  10,
		// Ak: [16]byte{},
	}
	// Set the flyover to the first hop of the xover hop. Hops are:
	// - [0] 111[0] -> 111[41]
	// - [1] 110[1] -> 110[0]
	// - [2] 110[0] -> 110[2]
	// - [3] 112[1] -> 112[0]
	r.SetFlyover(1, &flyoverData)

	// Check that the hop indeed has the flyover.
	require.NotNil(t, r.Hops[1])
	// The xover hop corresponds to the first segment, check its size:
	require.Equal(t, 8, int(r.Dec.PathMeta.SegLen[0]))
	// Check that the second segment doesn't have any flyovers:
	require.Equal(t, 6, int(r.Dec.PathMeta.SegLen[1]))
}

func TestWithScionPath(t *testing.T) {
	const referenceEpochTime uint32 = 123456
	referenceTime := util.SecsToTime(referenceEpochTime)

	p := createSnetScionPath(t, referenceTime)
	flyoverMap := createFlyovers(t, referenceEpochTime)
	require.Len(t, flyoverMap, 3) // Original flyovers are three.
	r, err := path.NewReservation(path.WithScionPath(p, flyoverMap))
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Len(t, flyoverMap, 0) // All flyovers were used.

	// The path contains two segments, i.e. one xover hop.
	// There should only be three flyovers, check it.
	// The hops are:			With Flyover
	// - [0] 111[0] -> 111[41]		*
	// - [1] 110[1] -> 110[0]		*
	// - [2] 110[0] -> 110[2]
	// - [3] 112[1] -> 112[0]		*
	require.Len(t, r.Hops, 4)
	checkHop(t, r.Hops[0], "1-ff00:0:111", 0, 41, true)
	checkHop(t, r.Hops[1], "1-ff00:0:110", 1, 2, true)
	checkHop(t, r.Hops[2], "1-ff00:0:110", 999, 999, false) // ingress and egress don't matter here
	checkHop(t, r.Hops[3], "1-ff00:0:112", 1, 0, true)
}

func TestFlyoversForPath(t *testing.T) {
	const referenceEpochTime uint32 = 123456
	referenceTime := util.SecsToTime(referenceEpochTime)

	p := createSnetScionPath(t, referenceTime)
	require.NotNil(t, p)

	flyovers := getFlyoversForPath(t, p, referenceEpochTime)
	require.Len(t, flyovers, 3)

	expectedFlyovers := createFlyovers(t, referenceEpochTime)
	require.EqualValues(t, expectedFlyovers, flyovers)
}

// createHummingbirdPath creates a valid Hummingbird path between 111 and 112 from the tiny topo.
// This path contains no flyovers.
func createHummingbirdPath(iniTime time.Time) *dphumm.Decoded {
	const hfValidity = 8

	dec := &dphumm.Decoded{
		Base: dphumm.Base{
			PathMeta: dphumm.MetaHdr{
				SegLen: [3]uint8{6, 6, 0},
			},
			NumINF:   2,
			NumLines: 4 * 3, // 4 non-flyover hops.
		},
		InfoFields: []dppath.InfoField{
			// up
			{
				ConsDir:   false,
				Timestamp: util.TimeToSecs(iniTime),
			},
			// down
			{
				ConsDir:   true,
				Timestamp: util.TimeToSecs(iniTime),
			},
		},
		FirstHopPerSeg: [2]uint8{2, 4}, // Second segment starts at index 2. There's no third one.
		HopFields: []dphumm.FlyoverHopField{
			// 111: 0->41 up
			{
				HopField: dppath.HopField{
					ConsIngress: 41,
					ConsEgress:  0,
					ExpTime:     hfValidity,
				},
			},
			// 110: 1->0  up
			{
				HopField: dppath.HopField{
					ConsIngress: 0,
					ConsEgress:  1,
					ExpTime:     hfValidity,
				},
			},
			// 110: 0->2  down
			{
				HopField: dppath.HopField{
					ConsIngress: 0,
					ConsEgress:  2,
					ExpTime:     hfValidity,
				},
			},
			// 112: 1->0  down
			{
				HopField: dppath.HopField{
					ConsIngress: 1,
					ConsEgress:  0,
					ExpTime:     hfValidity,
				},
			},
		},
	}
	return dec
}

// createScionPath creates a mock scion path between the tiny topology's 111 AS and 112 one.
func createScionPath(iniTime time.Time) *scion.Decoded {
	const hfValidity = 8

	dec := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				SegLen: [3]uint8{2, 2, 0},
			},
			NumINF:  2,
			NumHops: 4,
		},
		InfoFields: []dppath.InfoField{
			// up
			{
				ConsDir:   false,
				Timestamp: util.TimeToSecs(iniTime),
			},
			// down
			{
				ConsDir:   true,
				Timestamp: util.TimeToSecs(iniTime),
			},
		},
		HopFields: []dppath.HopField{
			// 111: 0->41 up
			{
				ConsIngress: 41,
				ConsEgress:  0,
				ExpTime:     hfValidity,
			},
			// 110: 1->0  up
			{
				ConsIngress: 0,
				ConsEgress:  1,
				ExpTime:     hfValidity,
			},
			// 110: 0->2  down
			{
				ConsIngress: 0,
				ConsEgress:  2,
				ExpTime:     hfValidity,
			},
			// 112: 1->0  down
			{
				ConsIngress: 1,
				ConsEgress:  0,
				ExpTime:     hfValidity,
			},
		},
	}
	return dec
}

func createSnetScionPath(t *testing.T, iniTime time.Time) path.Path {
	scion, err := path.NewSCIONFromDecoded(*createScionPath(iniTime))
	require.NoError(t, err)
	as111 := addr.MustParseIA("1-ff00:0:111")
	as110 := addr.MustParseIA("1-ff00:0:110")
	as112 := addr.MustParseIA("1-ff00:0:112")
	return path.Path{
		Src:           addr.MustParseIA("1-ff00:0:111"),
		Dst:           addr.MustParseIA("1-ff00:0:112"),
		DataplanePath: scion,
		Meta: snet.PathMetadata{
			MTU:    1500,
			Expiry: iniTime.Add(time.Hour),
			Interfaces: []snet.PathInterface{
				// First segment:
				{
					IA: as111,
					ID: 41,
				},
				{
					IA: as110,
					ID: 1,
				},
				// Second segment:
				{
					IA: as110,
					ID: 2,
				},
				{
					IA: as112,
					ID: 1,
				},
			},
		},
	}
}

// createFlyovers creates all the flyovers for the path 111->112 of the tiny topology.
func createFlyovers(t *testing.T, startTime uint32) path.FlyoverMap {
	m := make(path.FlyoverMap)
	{ // 111: 0 -> 41
		hop := path.BaseHop{
			IA:      addr.MustParseIA("1-ff00:0:111"),
			Ingress: 0,
			Egress:  41,
		}
		m[hop] = redeemFlyover(t, hop, startTime)
	}
	{ // 110: 1 ->  2
		hop := path.BaseHop{
			IA:      addr.MustParseIA("1-ff00:0:110"),
			Ingress: 1,
			Egress:  2,
		}
		m[hop] = redeemFlyover(t, hop, startTime)
	}
	{ // 112: 1 ->  0
		hop := path.BaseHop{
			IA:      addr.MustParseIA("1-ff00:0:112"),
			Ingress: 1,
			Egress:  0,
		}
		m[hop] = redeemFlyover(t, hop, startTime)
	}
	return m
}

func checkHop(t *testing.T, hop *path.FlyoverData, ia string, in uint16, eg uint16, isFlyover bool) {
	if isFlyover {
		require.NotNil(t, hop)
		require.Equal(t, isFlyover, hop.IsFlyover)
	} else {
		require.Nil(t, hop)
		return
	}
	require.Equal(t, addr.MustParseIA(ia), hop.IA)
	require.Equal(t, in, hop.Ingress)
	require.Equal(t, eg, hop.Egress)
}

func getPaths(t *testing.T, srcIA addr.IA, dstIA addr.IA) []snet.Path {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	daemonLocation := ""
	configDir := ""
	sd, err := daemon.NewAutoConnector(ctx,
		daemon.WithDaemon(daemonLocation),
		daemon.WithConfigDir(configDir),
	)
	require.NoError(t, err)
	paths, err := sd.Paths(ctx, dstIA, srcIA, types.PathReqFlags{})
	require.NoError(t, err)
	return paths
}

func getFlyoversForPath(t *testing.T, p snet.Path, startTime uint32) path.FlyoverMap {
	// Get the sequence of ingress->egress interfaces for each on-path AS.
	// Use p.Metadata().Interfaces for this. Include the initial 0->egress for the source AS,
	// and the final ingress->0 for the destination AS.
	t.Helper()
	flyovers := make(path.FlyoverMap)
	intfs := p.Metadata().Interfaces
	require.NotEmpty(t, intfs)

	baseHop := path.BaseHop{
		IA:      intfs[0].IA,
		Ingress: 0,
		Egress:  uint16(intfs[0].ID),
	}
	// For each found triplet <AS,ingress,egress> call redeemFlyover and store the result.
	flyover := redeemFlyover(t, baseHop, startTime)
	flyovers[baseHop] = flyover

	for i := 1; i < len(intfs); i += 2 {
		egress := uint16(0)
		if i+1 < len(intfs) {
			egress = uint16(intfs[i+1].ID)
		}
		baseHop = path.BaseHop{
			IA:      intfs[i].IA,
			Ingress: uint16(intfs[i].ID),
			Egress:  egress,
		}
		flyover = redeemFlyover(t, baseHop, startTime)
		flyovers[baseHop] = flyover
	}

	return flyovers
}

// redeemFlyover mocks the redemption of a flyover for a given AS, ingress, and egress interfaces.
// The real function will require a daemon.Connector to find a path to the given AS, or the path
// to the given AS.
func redeemFlyover(t *testing.T, baseHop path.BaseHop, startTime uint32) *path.FlyoverData {
	t.Helper()
	return &path.FlyoverData{
		BaseHop:   baseHop,
		IsFlyover: true,
		ResID:     1,
		StartTime: startTime,
		Duration:  10,
		Bw:        64,
		Ak:        [16]byte{},
	}
}
