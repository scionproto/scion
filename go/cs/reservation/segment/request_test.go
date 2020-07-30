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
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

func TestNewSetupReqFromCtrlMsg(t *testing.T) {
	ctrlMsg := newSetup()
	ts := util.SecsToTime(1)
	r, err := segment.NewSetupReqFromCtrlMsg(ctrlMsg, ts, nil)
	require.Error(t, err) // missing path
	p := newPath()
	r, err = segment.NewSetupReqFromCtrlMsg(ctrlMsg, ts, p)
	require.NoError(t, err)
	require.Equal(t, p, r.Path())
	checkRequest(t, ctrlMsg, r, ts)
	require.Equal(t, common.IFIDType(1), r.Ingress)
	require.Equal(t, common.IFIDType(2), r.Egress)
}

func TestRequestToCtrlMsg(t *testing.T) {
	ctrlMsg := newSetup()
	ts := util.SecsToTime(1)
	r, err := segment.NewSetupReqFromCtrlMsg(ctrlMsg, ts, newPath())
	require.NoError(t, err)
	anotherCtrlMsg := r.ToCtrlMsg()
	require.Equal(t, ctrlMsg, anotherCtrlMsg)
}

func TestNewTelesRequestFromCtrlMsg(t *testing.T) {
	ctrlMsg := newTelesSetup()
	ts := util.SecsToTime(1)
	r, err := segment.NewTelesRequestFromCtrlMsg(ctrlMsg, ts, nil)
	require.Error(t, err) // path is nil
	r, err = segment.NewTelesRequestFromCtrlMsg(ctrlMsg, ts, newPath())
	require.NoError(t, err)
	checkRequest(t, ctrlMsg.Setup, &r.SetupReq, ts)
	require.Equal(t, xtest.MustParseAS("ff00:cafe:1"), r.BaseID.ASID)
	require.Equal(t, xtest.MustParseHexString("deadbeef"), r.BaseID.Suffix[:])
}

func TestTelesRequestToCtrlMsg(t *testing.T) {
	ctrlMsg := newTelesSetup()
	ts := util.SecsToTime(1)
	r, _ := segment.NewTelesRequestFromCtrlMsg(ctrlMsg, ts, newPath())
	anotherCtrlMsg := r.ToCtrlMsg()
	require.Equal(t, ctrlMsg, anotherCtrlMsg)
}

func TestNewIndexConfirmationReqFromCtrlMsg(t *testing.T) {
	ctrlMsg := newIndexConfirmation()
	ts := util.SecsToTime(1)
	r, err := segment.NewIndexConfirmationReqFromCtrlMsg(ctrlMsg, ts, nil)
	require.Error(t, err) // nil path
	r, err = segment.NewIndexConfirmationReqFromCtrlMsg(ctrlMsg, ts, newPath())
	require.NoError(t, err)
	require.Equal(t, reservation.IndexNumber(ctrlMsg.Base.Index), r.Index)
	require.Equal(t, segment.IndexActive, r.State)
}

func TestIndexConfirmationReqToCtrlMsg(t *testing.T) {
	ctrlMsg := newIndexConfirmation()
	ts := util.SecsToTime(1)
	r, _ := segment.NewIndexConfirmationReqFromCtrlMsg(ctrlMsg, ts, newPath())
	r.State = segment.IndexTemporary
	_, err := r.ToCtrlMsg()
	require.Error(t, err)
	r, _ = segment.NewIndexConfirmationReqFromCtrlMsg(ctrlMsg, ts, newPath())
	anotherCtrlMsg, err := r.ToCtrlMsg()
	require.NoError(t, err)
	require.Equal(t, *ctrlMsg, *anotherCtrlMsg)
}

func TestNewCleanupReqFromCtrlMsg(t *testing.T) {
	ctrlMsg := newCleanup()
	ts := util.SecsToTime(1)
	r, err := segment.NewCleanupReqFromCtrlMsg(ctrlMsg, ts, nil)
	require.Error(t, err) // no path
	ctrlMsg = newCleanup()
	r, err = segment.NewCleanupReqFromCtrlMsg(ctrlMsg, ts, newPath())
	require.NoError(t, err)
	require.Equal(t, reservation.IndexNumber(ctrlMsg.Base.Index), r.Index)
	checkIDs(t, ctrlMsg.Base.ID, &r.ID)
}

func TestCleanupReqToCtrlMsg(t *testing.T) {
	ctrlMsg := newCleanup()
	ts := util.SecsToTime(1)
	r, _ := segment.NewCleanupReqFromCtrlMsg(ctrlMsg, ts, newPath())
	anotherCtrlMsg := r.ToCtrlMsg()
	require.Equal(t, ctrlMsg, anotherCtrlMsg)
}

func newBase(idx uint8) *colibri_mgmt.SegmentBase {
	return &colibri_mgmt.SegmentBase{
		ID:    newID(),
		Index: idx,
	}
}

func newSetup() *colibri_mgmt.SegmentSetup {
	return &colibri_mgmt.SegmentSetup{
		Base:     newBase(1),
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
		InfoField: xtest.MustParseHexString("16ebdb4f0d042500"),
		AllocationTrail: []*colibri_mgmt.AllocationBead{
			{
				AllocBW: 5,
				MaxBW:   6,
			},
		},
	}
}

func newTelesSetup() *colibri_mgmt.SegmentTelesSetup {
	return &colibri_mgmt.SegmentTelesSetup{
		Setup:  newSetup(),
		BaseID: newID(),
	}
}

func newIndexConfirmation() *colibri_mgmt.SegmentIndexConfirmation {
	return &colibri_mgmt.SegmentIndexConfirmation{
		Base:  newBase(2),
		State: proto.ReservationIndexState_active,
	}
}

func newCleanup() *colibri_mgmt.SegmentCleanup {
	return &colibri_mgmt.SegmentCleanup{
		Base: newBase(1),
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

func newID() *colibri_mgmt.SegmentReservationID {
	return &colibri_mgmt.SegmentReservationID{
		ASID:   xtest.MustParseHexString("ff00cafe0001"),
		Suffix: xtest.MustParseHexString("deadbeef"),
	}
}

func checkRequest(t *testing.T, segSetup *colibri_mgmt.SegmentSetup, r *segment.SetupReq,
	ts time.Time) {

	t.Helper()
	require.Equal(t, (*segment.Reservation)(nil), r.Reservation)
	require.Equal(t, ts, r.Timestamp)
	checkIDs(t, segSetup.Base.ID, &r.ID)
	require.Equal(t, segSetup.Base.Index, uint8(r.Index))
	require.Equal(t, segSetup.MinBW, uint8(r.MinBW))
	require.Equal(t, segSetup.MaxBW, uint8(r.MaxBW))
	require.Equal(t, segSetup.SplitCls, uint8(r.SplitCls))
	require.Equal(t, reservation.NewPathEndProps(
		segSetup.StartProps.Local, segSetup.StartProps.Transfer,
		segSetup.EndProps.Local, segSetup.EndProps.Transfer), r.PathProps)
	require.Len(t, r.AllocTrail, len(segSetup.AllocationTrail))
	for i := range segSetup.AllocationTrail {
		require.Equal(t, segSetup.AllocationTrail[i].AllocBW, uint8(r.AllocTrail[i].AllocBW))
		require.Equal(t, segSetup.AllocationTrail[i].MaxBW, uint8(r.AllocTrail[i].MaxBW))
	}
}

func checkIDs(t *testing.T, ctrlID *colibri_mgmt.SegmentReservationID, id *reservation.SegmentID) {
	t.Helper()
	expectedID := append(ctrlID.ASID, ctrlID.Suffix...)
	require.Equal(t, expectedID, id.ToRaw())
}
