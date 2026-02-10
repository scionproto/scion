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

package hummingbird_test

import (
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers/path"
	dphum "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/stretchr/testify/require"
)

func TestNewPathFromScion(t *testing.T) {
	scionExpTime := util.SecsToTime(12345)
	scionDec := createScionPath(scionExpTime)
	scionPath := &snetpath.SCION{
		Raw: make([]byte, scionDec.Len()),
	}
	err := scionDec.SerializeTo(scionPath.Raw)
	require.NoError(t, err)
	snetPath := snetpath.Path{
		Src:           addr.MustParseIA("1-ff00:0:111"),
		Dst:           addr.MustParseIA("1-ff00:0:112"),
		DataplanePath: *scionPath,
	}
	hum, err := hummingbird.NewPathFromScion(&snetPath, scionExpTime)
	require.NoError(t, err)
	dpHum, ok := hum.Dataplane().(snetpath.Hummingbird)
	require.True(t, ok)
	checkSamePath(t, scionDec, dpHum)

	// Repeat but with a path value instead of a pointer.
	hum, err = hummingbird.NewPathFromScion(snetPath, scionExpTime)
	require.NoError(t, err)
	dpHum, ok = hum.Dataplane().(snetpath.Hummingbird)
	require.True(t, ok)
	checkSamePath(t, scionDec, dpHum)
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
		InfoFields: []path.InfoField{
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
		HopFields: []path.HopField{
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

// checkSamePath checks that the scion decoded path, and the snet Hummingbird path are the same
// in terms of the interfaces it traverses, and how it would traverse them (best effort,
// no flyover).
func checkSamePath(t *testing.T, s *scion.Decoded, snetHum snetpath.Hummingbird) {
	h := dphum.Decoded{}
	err := h.DecodeFromBytes(snetHum.Raw)
	require.NoError(t, err)
	require.Equal(t, len(s.InfoFields), len(h.InfoFields))
	require.Equal(t, len(s.HopFields), len(h.HopFields))
	for i := range s.InfoFields {
		require.Equal(t, s.InfoFields[i].ConsDir, h.InfoFields[i].ConsDir)
		require.Equal(t, s.InfoFields[i].Peer, h.InfoFields[i].Peer)
		require.Equal(t, s.InfoFields[i].SegID, h.InfoFields[i].SegID)
		require.Equal(t, s.InfoFields[i].Timestamp, h.InfoFields[i].Timestamp)
	}
	for i := range s.HopFields {
		require.Equal(t, s.HopFields[i].ConsIngress, h.HopFields[i].HopField.ConsIngress)
		require.Equal(t, s.HopFields[i].ConsEgress, h.HopFields[i].HopField.ConsEgress)
		require.Equal(t, s.HopFields[i].IngressRouterAlert, h.HopFields[i].HopField.IngressRouterAlert)
		require.Equal(t, s.HopFields[i].EgressRouterAlert, h.HopFields[i].HopField.EgressRouterAlert)
		require.Equal(t, s.HopFields[i].ExpTime, h.HopFields[i].HopField.ExpTime)
		require.Equal(t, s.HopFields[i].Mac, h.HopFields[i].HopField.Mac)
	}
}
