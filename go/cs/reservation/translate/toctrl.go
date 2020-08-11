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
	"fmt"

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/cs/reservation/e2e"
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
	case *e2e.SetupReq:
		if !renewal {
			err = setE2ESetup(r, ctrl)
		} else {
			err = setE2ERenewal(r, ctrl)
		}
	case *e2e.CleanupReq:
		err = setE2ECleanup(r, ctrl)

	// responses (that move backwards in the reservation path):
	case *segment.ResponseSetupSuccess:
		if !renewal {
			err = setSegmentSetupSuccessResponse(r, ctrl)
		} else {
			err = setSegmentRenewalSuccessResponse(r, ctrl)
		}
	case *segment.ResponseSetupFailure:
		if !renewal {
			err = setSegmentSetupFailureResponse(r, ctrl)
		} else {
			err = setSegmentRenewalFailureResponse(r, ctrl)
		}
	case *segment.ResponseTeardownSuccess:
		err = setSegmentTeardownSuccessResponse(r, ctrl)
	case *segment.ResponseTeardownFailure:
		err = setSegmentTeardownFailureResponse(r, ctrl)
	case *segment.ResponseIndexConfirmationSuccess:
		err = setSegmentIndexConfirmationSuccessResponse(r, ctrl)
	case *segment.ResponseIndexConfirmationFailure:
		err = setSegmentIndexConfirmationFailureResponse(r, ctrl)
	case *segment.ResponseCleanupSuccess:
		err = setSegmentCleanupSuccessResponse(r, ctrl)
	case *segment.ResponseCleanupFailure:
		err = setSegmentCleanupFailureResponse(r, ctrl)
	case *e2e.ResponseSetupSuccess:
		if !renewal {
			err = setE2ESetupSuccessResponse(r, ctrl)
		} else {
			err = setE2ERenewalSuccessResponse(r, ctrl)
		}
	case *e2e.ResponseSetupFailure:
		if !renewal {
			err = setE2ESetupFailureResponse(r, ctrl)
		} else {
			err = setE2ERenewalFailureResponse(r, ctrl)
		}
	case *e2e.ResponseCleanupSuccess:
		err = setE2ECleanupSuccessResponse(r, ctrl)
	case *e2e.ResponseCleanupFailure:
		err = setE2ECleanupFailureResponse(r, ctrl)
	default:
		err = serrors.New("unknown application type", "type", fmt.Sprintf("%T", msg))
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

func newSegmentBaseFromResponse(msg *segment.Response) *colibri_mgmt.SegmentBase {
	return &colibri_mgmt.SegmentBase{
		ID:    NewCtrlSegmentReservationID(&msg.ID),
		Index: uint8(msg.Index),
	}
}

func newE2EBase(msg *e2e.Request) *colibri_mgmt.E2EBase {
	return &colibri_mgmt.E2EBase{
		ID:    NewCtrlE2EReservationID(&msg.ID),
		Index: uint8(msg.Index),
	}
}

func newE2EBaseFromResponse(msg *e2e.Response) *colibri_mgmt.E2EBase {
	return &colibri_mgmt.E2EBase{
		ID:    NewCtrlE2EReservationID(&msg.ID),
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
func thisIsAResponse(ctrl *colibri_mgmt.ColibriRequestPayload, accepted bool) {
	ctrl.Response = &colibri_mgmt.Response{
		Accepted: accepted,
	}
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

func setSegmentIndexConfirmation(msg *segment.IndexConfirmationReq,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

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

func setE2ESetup(msg *e2e.SetupReq, ctrl *colibri_mgmt.ColibriRequestPayload) error {
	thisIsARequest(ctrl)
	ctrl.Request.E2ESetup = &colibri_mgmt.E2ESetup{
		Base:  newE2EBase(&msg.Request),
		Token: msg.Token.ToRaw(),
	}
	ctrl.Request.Which = proto.Request_Which_e2eSetup
	return nil
}

func setE2ERenewal(msg *e2e.SetupReq, ctrl *colibri_mgmt.ColibriRequestPayload) error {
	thisIsARequest(ctrl)
	ctrl.Request.E2ERenewal = &colibri_mgmt.E2ESetup{
		Base:  newE2EBase(&msg.Request),
		Token: msg.Token.ToRaw(),
	}
	ctrl.Request.Which = proto.Request_Which_e2eRenewal
	return nil
}

func setE2ECleanup(msg *e2e.CleanupReq, ctrl *colibri_mgmt.ColibriRequestPayload) error {
	thisIsARequest(ctrl)
	ctrl.Request.E2ECleanup = &colibri_mgmt.E2ECleanup{
		Base: newE2EBase(&msg.Request),
	}
	ctrl.Request.Which = proto.Request_Which_e2eCleanup
	return nil
}

func setSegmentSetupSuccessResponse(msg *segment.ResponseSetupSuccess,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	thisIsAResponse(ctrl, true)
	ctrl.Response.SegmentSetup = &colibri_mgmt.SegmentSetupRes{
		Base:  newSegmentBaseFromResponse(&msg.Response),
		Which: proto.SegmentSetupResData_Which_token,
		Token: msg.Token.ToRaw(),
	}
	ctrl.Response.Which = proto.Response_Which_segmentSetup
	return nil
}

func setSegmentSetupFailureResponse(msg *segment.ResponseSetupFailure,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	thisIsAResponse(ctrl, false)
	ctrl.Response.SegmentSetup = &colibri_mgmt.SegmentSetupRes{
		Base:    newSegmentBaseFromResponse(&msg.Response),
		Which:   proto.SegmentSetupResData_Which_failure,
		Failure: newSegmentSetup(&msg.FailedSetup),
	}
	ctrl.Response.Which = proto.Response_Which_segmentSetup
	return nil
}

func setSegmentRenewalSuccessResponse(msg *segment.ResponseSetupSuccess,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	thisIsAResponse(ctrl, true)
	ctrl.Response.SegmentRenewal = &colibri_mgmt.SegmentSetupRes{
		Base:  newSegmentBaseFromResponse(&msg.Response),
		Which: proto.SegmentSetupResData_Which_token,
		Token: msg.Token.ToRaw(),
	}
	ctrl.Response.Which = proto.Response_Which_segmentRenewal
	return nil
}

func setSegmentRenewalFailureResponse(msg *segment.ResponseSetupFailure,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	thisIsAResponse(ctrl, false)
	ctrl.Response.SegmentRenewal = &colibri_mgmt.SegmentSetupRes{
		Base:    newSegmentBaseFromResponse(&msg.Response),
		Which:   proto.SegmentSetupResData_Which_failure,
		Failure: newSegmentSetup(&msg.FailedSetup),
	}
	ctrl.Response.Which = proto.Response_Which_segmentRenewal
	return nil
}
func setSegmentTeardownSuccessResponse(msg *segment.ResponseTeardownSuccess,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	thisIsAResponse(ctrl, true)
	ctrl.Response.SegmentTeardown = &colibri_mgmt.SegmentTeardownRes{
		Base: newSegmentBaseFromResponse(&msg.Response),
	}
	ctrl.Response.Which = proto.Response_Which_segmentTeardown
	return nil
}

func setSegmentTeardownFailureResponse(msg *segment.ResponseTeardownFailure,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	thisIsAResponse(ctrl, false)
	ctrl.Response.SegmentTeardown = &colibri_mgmt.SegmentTeardownRes{
		Base:      newSegmentBaseFromResponse(&msg.Response),
		ErrorCode: msg.ErrorCode,
	}
	ctrl.Response.Which = proto.Response_Which_segmentTeardown
	return nil
}

func setSegmentIndexConfirmationSuccessResponse(msg *segment.ResponseIndexConfirmationSuccess,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	thisIsAResponse(ctrl, true)
	ctrl.Response.SegmentIndexConfirmation = &colibri_mgmt.SegmentIndexConfirmationRes{
		Base: newSegmentBaseFromResponse(&msg.Response),
	}
	ctrl.Response.Which = proto.Response_Which_segmentIndexConfirmation
	return nil
}

func setSegmentIndexConfirmationFailureResponse(msg *segment.ResponseIndexConfirmationFailure,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	thisIsAResponse(ctrl, false)
	ctrl.Response.SegmentIndexConfirmation = &colibri_mgmt.SegmentIndexConfirmationRes{
		Base:      newSegmentBaseFromResponse(&msg.Response),
		ErrorCode: msg.ErrorCode,
	}
	ctrl.Response.Which = proto.Response_Which_segmentIndexConfirmation
	return nil
}

func setSegmentCleanupSuccessResponse(msg *segment.ResponseCleanupSuccess,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	thisIsAResponse(ctrl, true)
	ctrl.Response.SegmentCleanup = &colibri_mgmt.SegmentCleanupRes{
		Base: newSegmentBaseFromResponse(&msg.Response),
	}
	ctrl.Response.Which = proto.Response_Which_segmentCleanup
	return nil
}

func setSegmentCleanupFailureResponse(msg *segment.ResponseCleanupFailure,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	thisIsAResponse(ctrl, false)
	ctrl.Response.SegmentCleanup = &colibri_mgmt.SegmentCleanupRes{
		Base:      newSegmentBaseFromResponse(&msg.Response),
		ErrorCode: msg.ErrorCode,
	}
	ctrl.Response.Which = proto.Response_Which_segmentCleanup
	return nil
}

func setE2ESetupSuccessResponse(msg *e2e.ResponseSetupSuccess,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	thisIsAResponse(ctrl, true)
	ctrl.Response.E2ESetup = &colibri_mgmt.E2ESetupRes{
		Base:  newE2EBaseFromResponse(&msg.Response),
		Which: proto.E2ESetupResData_Which_success,
		Success: &colibri_mgmt.E2ESetupSuccess{
			Token: msg.Token.ToRaw(),
		},
	}
	ctrl.Response.Which = proto.Response_Which_e2eSetup
	return nil
}

func setE2ERenewalSuccessResponse(msg *e2e.ResponseSetupSuccess,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	thisIsAResponse(ctrl, true)
	ctrl.Response.E2ERenewal = &colibri_mgmt.E2ESetupRes{
		Base:  newE2EBaseFromResponse(&msg.Response),
		Which: proto.E2ESetupResData_Which_success,
		Success: &colibri_mgmt.E2ESetupSuccess{
			Token: msg.Token.ToRaw(),
		},
	}
	ctrl.Response.Which = proto.Response_Which_e2eRenewal
	return nil
}

func setE2ESetupFailureResponse(msg *e2e.ResponseSetupFailure,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	maxBWs := make([]uint8, len(msg.MaxBWs))
	for i := range msg.MaxBWs {
		maxBWs[i] = uint8(msg.MaxBWs[i])
	}
	thisIsAResponse(ctrl, false)
	ctrl.Response.E2ESetup = &colibri_mgmt.E2ESetupRes{
		Base:  newE2EBaseFromResponse(&msg.Response),
		Which: proto.E2ESetupResData_Which_failure,
		Failure: &colibri_mgmt.E2ESetupFailure{
			ErrorCode: msg.ErrorCode,
			InfoField: msg.InfoField.ToRaw(),
			MaxBWs:    maxBWs,
		},
	}
	ctrl.Response.Which = proto.Response_Which_e2eSetup
	return nil
}

func setE2ERenewalFailureResponse(msg *e2e.ResponseSetupFailure,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	maxBWs := make([]uint8, len(msg.MaxBWs))
	for i := range msg.MaxBWs {
		maxBWs[i] = uint8(msg.MaxBWs[i])
	}
	thisIsAResponse(ctrl, false)
	ctrl.Response.E2ERenewal = &colibri_mgmt.E2ESetupRes{
		Base:  newE2EBaseFromResponse(&msg.Response),
		Which: proto.E2ESetupResData_Which_failure,
		Failure: &colibri_mgmt.E2ESetupFailure{
			ErrorCode: msg.ErrorCode,
			InfoField: msg.InfoField.ToRaw(),
			MaxBWs:    maxBWs,
		},
	}
	ctrl.Response.Which = proto.Response_Which_e2eRenewal
	return nil
}

func setE2ECleanupSuccessResponse(msg *e2e.ResponseCleanupSuccess,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	thisIsAResponse(ctrl, true)
	ctrl.Response.E2ECleanup = &colibri_mgmt.E2ECleanupRes{
		Base: newE2EBaseFromResponse(&msg.Response),
	}
	ctrl.Response.Which = proto.Response_Which_e2eCleanup
	return nil
}

func setE2ECleanupFailureResponse(msg *e2e.ResponseCleanupFailure,
	ctrl *colibri_mgmt.ColibriRequestPayload) error {

	thisIsAResponse(ctrl, false)
	ctrl.Response.E2ECleanup = &colibri_mgmt.E2ECleanupRes{
		Base:      newE2EBaseFromResponse(&msg.Response),
		ErrorCode: msg.ErrorCode,
	}
	ctrl.Response.Which = proto.Response_Which_e2eCleanup
	return nil
}
