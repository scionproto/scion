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

package segment_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestNewRequestFromCtrlMsg(t *testing.T) {
	segSetup := newSegSetup()
	ts := time.Unix(1, 0)
	r := segment.NewRequestFromCtrlMsg(segSetup, ts)
	checkRequest(t, segSetup, r, ts)
}

func TestRequestToCtrlMsg(t *testing.T) {
	segSetup := newSegSetup()
	ts := time.Unix(1, 0)
	r := segment.NewRequestFromCtrlMsg(segSetup, ts)
	anotherSegSetup := r.ToCtrlMsg()
	require.Equal(t, segSetup, anotherSegSetup)
}

func TestNewTelesRequestFromCtrlMsg(t *testing.T) {
	telesReq := &colibri_mgmt.SegmentTelesSetup{
		Setup: newSegSetup(),
		BaseID: &colibri_mgmt.SegmentReservationID{
			ASID:   xtest.MustParseHexString("ff00cafe0001"),
			Suffix: xtest.MustParseHexString("deadbeef"),
		},
	}
	ts := time.Unix(1, 0)
	r, err := segment.NewTelesRequestFromCtrlMsg(telesReq, ts)
	require.NoError(t, err)

	checkRequest(t, telesReq.Setup, &r.SetupReq, ts)
	require.Equal(t, xtest.MustParseAS("ff00:cafe:1"), r.BaseID.ASID)
	require.Equal(t, xtest.MustParseHexString("deadbeef"), r.BaseID.Suffix[:])
}

func newSegSetup() *colibri_mgmt.SegmentSetup {
	return &colibri_mgmt.SegmentSetup{
		MinBW:    1,
		MaxBW:    2,
		SplitCls: 3,
		StartProps: colibri_mgmt.PathEndProps{
			Local:    true,
			Transfer: false,
		},
		EndProps: colibri_mgmt.PathEndProps{
			Local:    false,
			Transfer: true,
		},
		AllocationTrail: []*colibri_mgmt.AllocationBeads{
			{
				AllocBW: 5,
				MaxBW:   6,
			},
		},
	}
}

func checkRequest(t *testing.T, segSetup *colibri_mgmt.SegmentSetup, r *segment.SetupReq,
	ts time.Time) {

	require.Equal(t, (*segment.Reservation)(nil), r.Reservation)
	require.Equal(t, ts, r.Timestamp)
	require.Equal(t, segSetup.MinBW, r.MinBW)
	require.Equal(t, segSetup.MaxBW, r.MaxBW)
	require.Equal(t, segSetup.SplitCls, r.SplitCls)
	require.Equal(t, reservation.NewPathEndProps(
		segSetup.StartProps.Local, segSetup.StartProps.Transfer,
		segSetup.EndProps.Local, segSetup.EndProps.Transfer), r.PathProps)
	require.Len(t, r.AllocTrail, len(segSetup.AllocationTrail))
	for i := range segSetup.AllocationTrail {
		require.Equal(t, segSetup.AllocationTrail[i].AllocBW, r.AllocTrail[i].AllocBW)
		require.Equal(t, segSetup.AllocationTrail[i].MaxBW, r.AllocTrail[i].MaxBW)
	}
}
