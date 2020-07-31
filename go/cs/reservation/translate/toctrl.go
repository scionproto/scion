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

package translate

import (
	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/proto"
)

// NewCtrlFromMsg translates the application type "msg" into a capnp one.
func NewCtrlFromMsg(msg base.MessageWithPath, renewal bool) (
	*colibri_mgmt.ColibriRequestPayload, error) {

	ctrl := &colibri_mgmt.ColibriRequestPayload{}
	var err error
	switch r := msg.(type) {
	// requests (those that move forward in the reservation path):
	case *segment.SetupReq:
		if !renewal {
			err = setSegmentSetup(r, ctrl)
		} else {
			err = setSegmentRenewal(r, ctrl)
		}
	case *segment.SetupTelesReq:
		if !renewal {
			err = setSegmentTelesSetup(r, ctrl)
		} else {
			err = setSegmentTelesRenewal(r, ctrl)
		}
	case *segment.TeardownReq:
		err = setSegmentTeardown(r, ctrl)
	case *segment.IndexConfirmationReq:
		err = setSegmentIndexConfirmation(r, ctrl)
	case *segment.CleanupReq:
		err = setSegmentCleanup(r, ctrl)
	// case *e2e.SetupReqTODO:
	// 	if !renewal{}
	// case *e2e.CleanupReq:
	// responses (that move backwards in the reservation path):
	case *segment.ResponseSetupSuccess:
		err = nil
	}
	return ctrl, err
}

func NewCtrlSegmentReservationID(ID *reservation.SegmentID) *colibri_mgmt.SegmentReservationID {
	buf := ID.ToRaw()
	return &colibri_mgmt.SegmentReservationID{
		ASID:   buf[:6],
		Suffix: buf[6:],
	}
}

func NewCtrlE2EReservationID(ID *reservation.E2EID) *colibri_mgmt.E2EReservationID {
	buf := ID.ToRaw()
	return &colibri_mgmt.E2EReservationID{
		ASID:   buf[:6],
		Suffix: buf[6:],
	}
}

func newSegmentBase(msg *segment.Request) *colibri_mgmt.SegmentBase {
	return &colibri_mgmt.SegmentBase{
		ID:    NewCtrlSegmentReservationID(&msg.ID),
		Index: uint8(msg.Index),
	}
}

func newIndexState(s segment.IndexState) (proto.ReservationIndexState, error) {
	switch s {
	case segment.IndexPending:
		return proto.ReservationIndexState_pending, nil
	case segment.IndexActive:
		return proto.ReservationIndexState_active, nil
	default:
		return 0, serrors.New("cannot convert index state to control message", "state", s)
	}
}

func newSegmentSetup(msg *segment.SetupReq) *colibri_mgmt.SegmentSetup {
	c := &colibri_mgmt.SegmentSetup{
		Base:     newSegmentBase(&msg.Request),
		MinBW:    uint8(msg.MinBW),
		MaxBW:    uint8(msg.MaxBW),
		SplitCls: uint8(msg.SplitCls),
		StartProps: colibri_mgmt.PathEndProps{
			Local:    (msg.PathProps & reservation.StartLocal) != 0,
			Transfer: (msg.PathProps & reservation.StartTransfer) != 0,
		},
		EndProps: colibri_mgmt.PathEndProps{
			Local:    (msg.PathProps & reservation.EndLocal) != 0,
			Transfer: (msg.PathProps & reservation.EndTransfer) != 0,
		},
		InfoField:       msg.InfoField.ToRaw(),
		AllocationTrail: make([]*colibri_mgmt.AllocationBead, len(msg.AllocTrail)),
	}
	for i, bead := range msg.AllocTrail {
		c.AllocationTrail[i] = &colibri_mgmt.AllocationBead{
			AllocBW: uint8(bead.AllocBW),
			MaxBW:   uint8(bead.MaxBW),
		}
	}
	return c
}

func thisIsARequest(ctrl *colibri_mgmt.ColibriRequestPayload) {
	ctrl.Request = &colibri_mgmt.Request{}
	ctrl.Which = proto.ColibriRequestPayload_Which_request
}
func thisIsAResponse(ctrl *colibri_mgmt.ColibriRequestPayload) {
	ctrl.Response = &colibri_mgmt.Response{}
	ctrl.Which = proto.ColibriRequestPayload_Which_response
}

func setSegmentSetup(msg *segment.SetupReq, ctrl *colibri_mgmt.ColibriRequestPayload) error {
	thisIsARequest(ctrl)
	ctrl.Request.SegmentSetup = newSegmentSetup(msg)
	ctrl.Request.Which = proto.Request_Which_segmentSetup
	return nil
}

func setSegmentRenewal(msg *segment.SetupReq, ctrl *colibri_mgmt.ColibriRequestPayload) error {
	thisIsARequest(ctrl)
	ctrl.Request.SegmentRenewal = newSegmentSetup(msg)
	ctrl.Request.Which = proto.Request_Which_segmentRenewal
	return nil
}

func setSegmentTelesSetup(msg *segment.SetupTelesReq, ctrl *colibri_mgmt.ColibriRequestPayload) error {
	thisIsARequest(ctrl)
	ctrl.Request.SegmentTelesSetup = &colibri_mgmt.SegmentTelesSetup{
		Setup:  newSegmentSetup(&msg.SetupReq),
		BaseID: NewCtrlSegmentReservationID(&msg.BaseID),
	}
	ctrl.Request.Which = proto.Request_Which_segmentTelesSetup
	return nil
}

func setSegmentTelesRenewal(msg *segment.SetupTelesReq, ctrl *colibri_mgmt.ColibriRequestPayload) error {
	thisIsARequest(ctrl)
	ctrl.Request.SegmentTelesRenewal = &colibri_mgmt.SegmentTelesSetup{
		Setup:  newSegmentSetup(&msg.SetupReq),
		BaseID: NewCtrlSegmentReservationID(&msg.BaseID),
	}
	ctrl.Request.Which = proto.Request_Which_segmentTelesRenewal
	return nil
}

func setSegmentTeardown(msg *segment.TeardownReq, ctrl *colibri_mgmt.ColibriRequestPayload) error {
	thisIsARequest(ctrl)
	ctrl.Request.SegmentTeardown = &colibri_mgmt.SegmentTeardownReq{
		Base: newSegmentBase(&msg.Request),
	}
	ctrl.Request.Which = proto.Request_Which_segmentTeardown
	return nil
}

func setSegmentIndexConfirmation(msg *segment.IndexConfirmationReq, ctrl *colibri_mgmt.ColibriRequestPayload) error {
	thisIsARequest(ctrl)
	st, err := newIndexState(msg.State)
	if err != nil {
		return err
	}
	ctrl.Request.SegmentIndexConfirmation = &colibri_mgmt.SegmentIndexConfirmation{
		Base:  newSegmentBase(&msg.Request),
		State: st,
	}
	ctrl.Request.Which = proto.Request_Which_segmentIndexConfirmation
	return nil
}

func setSegmentCleanup(msg *segment.CleanupReq, ctrl *colibri_mgmt.ColibriRequestPayload) error {
	thisIsARequest(ctrl)
	ctrl.Request.SegmentCleanup = &colibri_mgmt.SegmentCleanup{
		Base: newSegmentBase(&msg.Request),
	}
	ctrl.Request.Which = proto.Request_Which_segmentCleanup
	return nil
}
