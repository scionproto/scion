// Copyright 2020 ETH Zurich, Anapaya Systems
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

package e2e

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/reservation/segmenttest"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestNewRequest(t *testing.T) {
	_, err := NewRequest(util.SecsToTime(1), nil, 1, nil)
	require.Error(t, err)
	_, err = NewRequest(util.SecsToTime(1), nil, 1, segmenttest.NewTestPath())
	require.Error(t, err)
	id, err := reservation.NewE2EID(xtest.MustParseAS("ff00:0:111"),
		xtest.MustParseHexString("beefcafebeefcafebeef"))
	require.NoError(t, err)
	r, err := NewRequest(util.SecsToTime(1), id, 1, segmenttest.NewTestPath())
	require.NoError(t, err)
	require.Equal(t, util.SecsToTime(1), r.Timestamp)
	require.Equal(t, id, &r.ID)
	require.Equal(t, reservation.IndexNumber(1), r.Index)
	require.Equal(t, segmenttest.NewTestPath(), r.RequestMetadata.Path())
}

func TestNewSetupRequest(t *testing.T) {
	_, err := NewSetupRequest(nil, nil, nil, 5, nil)
	require.Error(t, err)
	id, err := reservation.NewE2EID(xtest.MustParseAS("ff00:0:111"),
		xtest.MustParseHexString("beefcafebeefcafebeef"))
	require.NoError(t, err)
	path := segmenttest.NewTestPath()
	baseReq, err := NewRequest(util.SecsToTime(1), id, 1, path)
	require.NoError(t, err)
	_, err = NewSetupRequest(baseReq, nil, nil, 5, nil)
	require.Error(t, err)

	segmentRsvs := make([]reservation.SegmentID, 0)
	_, err = NewSetupRequest(baseReq, segmentRsvs, nil, 5, nil)
	require.Error(t, err)
	segmentASCount := make([]uint8, 0)
	_, err = NewSetupRequest(baseReq, segmentRsvs, segmentASCount, 5, nil)
	require.Error(t, err)
	trail := make([]reservation.BWCls, 0)
	_, err = NewSetupRequest(baseReq, segmentRsvs, segmentASCount, 5, trail)
	require.Error(t, err)

	cases := map[string]struct {
		ASCountPerSegment []uint8
		TrailLength       int
		TotalASCount      int
		SegmentIndex      int
		PathLocation      PathLocation
		IsTransfer        bool
	}{
		// "3-2-4 at 0" means:
		// 3 segments, with 3 ASes in the first one, 2 and 4 in the others. Trail has 0 components
		"2 at 0": {
			ASCountPerSegment: []uint8{2},
			TrailLength:       0,
			TotalASCount:      2,
			SegmentIndex:      0,
			PathLocation:      Source,
			IsTransfer:        false,
		},
		"2 at 1": {
			ASCountPerSegment: []uint8{2},
			TrailLength:       1,
			TotalASCount:      2,
			SegmentIndex:      0,
			PathLocation:      Transit,
			IsTransfer:        false,
		},
		"2 at 2": {
			ASCountPerSegment: []uint8{2},
			TrailLength:       2,
			TotalASCount:      2,
			SegmentIndex:      0,
			PathLocation:      Destination,
			IsTransfer:        false,
		},
		"3-4-5 at 0": {
			ASCountPerSegment: []uint8{3, 4, 5},
			TrailLength:       0,
			TotalASCount:      10,
			SegmentIndex:      0,
			PathLocation:      Source,
			IsTransfer:        false,
		},
		"3-4-5 at 1": {
			ASCountPerSegment: []uint8{3, 4, 5},
			TrailLength:       1,
			TotalASCount:      10,
			SegmentIndex:      0,
			PathLocation:      Transit,
			IsTransfer:        false,
		},
		"3-4-5 at 2": {
			ASCountPerSegment: []uint8{3, 4, 5},
			TrailLength:       2,
			TotalASCount:      10,
			SegmentIndex:      0,
			PathLocation:      Transit,
			IsTransfer:        true,
		},
		"3-4-5 at 3": {
			ASCountPerSegment: []uint8{3, 4, 5},
			TrailLength:       3,
			TotalASCount:      10,
			SegmentIndex:      1,
			PathLocation:      Transit,
			IsTransfer:        false,
		},
		"3-4-5 at 5": {
			ASCountPerSegment: []uint8{3, 4, 5},
			TrailLength:       5,
			TotalASCount:      10,
			SegmentIndex:      1,
			PathLocation:      Transit,
			IsTransfer:        true,
		},
		"3-4-5 at 6": {
			ASCountPerSegment: []uint8{3, 4, 5},
			TrailLength:       6,
			TotalASCount:      10,
			SegmentIndex:      2,
			PathLocation:      Transit,
			IsTransfer:        false,
		},
		"3-4-5 at 9": {
			ASCountPerSegment: []uint8{3, 4, 5},
			TrailLength:       9,
			TotalASCount:      10,
			SegmentIndex:      2,
			PathLocation:      Transit,
			IsTransfer:        false,
		},
		"3-4-5 at 10": {
			ASCountPerSegment: []uint8{3, 4, 5},
			TrailLength:       10,
			TotalASCount:      10,
			SegmentIndex:      2,
			PathLocation:      Destination,
			IsTransfer:        false,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			segmentRsvs := make([]reservation.SegmentID, len(tc.ASCountPerSegment))
			for i := range segmentRsvs {
				segmentRsvs[i] = *newTestSegmentID(t)
			}
			trail := make([]reservation.BWCls, tc.TrailLength)
			for i := range trail {
				trail[i] = 5
			}
			r, err := NewSetupRequest(baseReq, segmentRsvs, tc.ASCountPerSegment, 5, trail)
			require.NoError(t, err)
			require.Equal(t, tc.TotalASCount, r.totalASCount)
			require.Equal(t, tc.SegmentIndex, r.currentASSegmentRsvIndex)
			require.Equal(t, tc.PathLocation, r.Location())
			require.Equal(t, tc.IsTransfer, r.Transfer())
		})
	}
}

func TestInterface(t *testing.T) {
	id, err := reservation.NewE2EID(xtest.MustParseAS("ff00:0:111"),
		xtest.MustParseHexString("beefcafebeefcafebeef"))
	require.NoError(t, err)
	path := segmenttest.NewTestPath()
	baseReq, err := NewRequest(util.SecsToTime(1), id, 1, path)
	require.NoError(t, err)
	segmentIDs := []reservation.SegmentID{*newTestSegmentID(t)}

	r, err := NewSetupRequest(baseReq, segmentIDs, []uint8{2}, 5, nil)
	require.NoError(t, err)
	tok, err := reservation.TokenFromRaw(xtest.MustParseHexString(
		"16ebdb4f0d042500003f001002bad1ce003f001002facade"))
	require.NoError(t, err)
	success := SetupReqSuccess{
		SetupReq: *r,
		Token:    *tok,
	}
	require.Equal(t, r, success.GetCommonSetupReq())
	failure := SetupReqFailure{
		SetupReq:  *r,
		ErrorCode: 6,
	}
	require.Equal(t, r, failure.GetCommonSetupReq())
}

// this fcn is helpful here to add segment reservations in the e2e setup request.
func newTestSegmentID(t *testing.T) *reservation.SegmentID {
	t.Helper()
	id, err := reservation.NewSegmentID(xtest.MustParseAS("ff00:0:1"),
		xtest.MustParseHexString("deadbeef"))
	require.NoError(t, err)
	return id
}
