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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestNewSetupReqFromCtrlMsg(t *testing.T) {
	segSetup := newSegSetup()
	ts := time.Unix(1, 0)
	r, err := segment.NewSetupReqFromCtrlMsg(segSetup, ts, nil)
	require.Error(t, err)
	p := newPath()
	r, err = segment.NewSetupReqFromCtrlMsg(segSetup, ts, p)
	require.NoError(t, err)
	require.Equal(t, *p, r.Path)
	checkRequest(t, segSetup, r, ts)
}

func TestRequestToCtrlMsg(t *testing.T) {
	segSetup := newSegSetup()
	ts := time.Unix(1, 0)
	r, err := segment.NewSetupReqFromCtrlMsg(segSetup, ts, newPath())
	require.NoError(t, err)
	anotherSegSetup := r.ToCtrlMsg()
	require.Equal(t, segSetup, anotherSegSetup)
}

func TestRequestIngressEgressIFIDs(t *testing.T) {
	segSetup := newSegSetup()
	ts := time.Unix(1, 0)
	p := newPath()
	r, _ := segment.NewSetupReqFromCtrlMsg(segSetup, ts, p)
	in, e, err := r.IngressEgressIFIDs()
	require.NoError(t, err)
	require.Equal(t, common.IFIDType(1), in)
	require.Equal(t, common.IFIDType(2), e)
}

func TestNewTelesRequestFromCtrlMsg(t *testing.T) {
	telesReq := newSegTelesSetup()
	ts := time.Unix(1, 0)
	r, err := segment.NewTelesRequestFromCtrlMsg(telesReq, ts, newPath())
	require.NoError(t, err)

	checkRequest(t, telesReq.Setup, &r.SetupReq, ts)
	require.Equal(t, xtest.MustParseAS("ff00:cafe:1"), r.BaseID.ASID)
	require.Equal(t, xtest.MustParseHexString("deadbeef"), r.BaseID.Suffix[:])
}

func TestTelesRequestToCtrlMsg(t *testing.T) {
	segSetup := newSegTelesSetup()
	ts := time.Unix(1, 0)
	r, _ := segment.NewTelesRequestFromCtrlMsg(segSetup, ts, newPath())
	anotherSegSetup := r.ToCtrlMsg()
	require.Equal(t, segSetup, anotherSegSetup)
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

// new path with one segment consisting on 3 hopfields: (0,2)->(1,2)->(1,0)
func newPath() *spath.Path {
	path := &spath.Path{
		InfOff: 0,
		HopOff: spath.InfoFieldLength + spath.HopFieldLength, // second hop field
		Raw:    make([]byte, spath.InfoFieldLength+3*spath.HopFieldLength),
	}
	inf := spath.InfoField{ConsDir: true, ISD: 1, Hops: 3}
	inf.Write(path.Raw)

	hf := &spath.HopField{ConsEgress: 2}
	hf.Write(path.Raw[spath.InfoFieldLength:])
	hf = &spath.HopField{ConsIngress: 1, ConsEgress: 2}
	hf.Write(path.Raw[spath.InfoFieldLength+spath.HopFieldLength:])
	hf = &spath.HopField{ConsIngress: 1}
	hf.Write(path.Raw[spath.InfoFieldLength+spath.HopFieldLength*2:])

	return path
}

func newSegTelesSetup() *colibri_mgmt.SegmentTelesSetup {
	return &colibri_mgmt.SegmentTelesSetup{
		Setup: newSegSetup(),
		BaseID: &colibri_mgmt.SegmentReservationID{
			ASID:   xtest.MustParseHexString("ff00cafe0001"),
			Suffix: xtest.MustParseHexString("deadbeef"),
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
