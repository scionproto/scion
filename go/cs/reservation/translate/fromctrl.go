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
	"encoding/hex"
	"time"

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/cs/reservation/e2e"
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/proto"
)

// NewMsgFromCtrl takes a colibri ctrl message and returns a new application type.
// the ColibriPath comes from the  packet that encapsulates the ctrl payload.
func NewMsgFromCtrl(ctrl *colibri_mgmt.ColibriRequestPayload, path base.ColibriPath) (
	base.MessageWithPath, error) {

	if ctrl == nil {
		return nil, serrors.New("nil ctrl message", "type", "ColibriRequestPayload")
	}
	ts := reservation.Tick(ctrl.Timestamp).ToTime()
	switch ctrl.Which {
	case proto.ColibriRequestPayload_Which_request:
		return newRequestFromCtrl(ctrl.Request, ts, path)
	case proto.ColibriRequestPayload_Which_response:
		return newResponseFromCtrl(ctrl.Response, ts, path)
	default:
		return nil, serrors.New("invalid ctrl message", "ctrl", ctrl.Which.String())
	}
}

// NewIndexStateFromCtrl converts a proto reservation index state into its application type.
func NewIndexStateFromCtrl(st proto.ReservationIndexState) (segment.IndexState, error) {
	var state segment.IndexState
	switch st {
	case proto.ReservationIndexState_pending:
		state = segment.IndexPending
	case proto.ReservationIndexState_active:
		state = segment.IndexActive
	default:
		return 0, serrors.New("unknown index_state in ctrl variable", "index_state", st)
	}
	return state, nil
}

// NewSegmentIDFromCtrl converts a segment id from ctrl to its application type.
func NewSegmentIDFromCtrl(ctrl *colibri_mgmt.SegmentReservationID) (
	*reservation.SegmentID, error) {

	if ctrl == nil {
		return nil, nil
	}
	id, err := reservation.SegmentIDFromRawBuffers(ctrl.ASID, ctrl.Suffix)
	if err != nil {
		return nil, serrors.WrapStr("converting segment id", err)
	}
	return id, nil
}

// NewE2EIDFromCtrl converts a segment id from ctrl to its application type.
func NewE2EIDFromCtrl(ctrl *colibri_mgmt.E2EReservationID) (
	*reservation.E2EID, error) {

	if ctrl == nil {
		return nil, nil
	}
	id, err := reservation.E2EIDFromRawBuffers(ctrl.ASID, ctrl.Suffix)
	if err != nil {
		return nil, serrors.WrapStr("converting e2e id", err)
	}
	return id, nil
}

func newRequestFromCtrl(ctrl *colibri_mgmt.Request, ts time.Time, path base.ColibriPath) (
	base.MessageWithPath, error) {

	if ctrl == nil {
		return nil, serrors.New("nil ctrl message", "type", "Request")
	}
	switch ctrl.Which {
	case proto.Request_Which_segmentSetup:
		return newRequestSegmentSetup(ctrl.SegmentSetup, ts, path)
	case proto.Request_Which_segmentRenewal:
		return newRequestSegmentSetup(ctrl.SegmentRenewal, ts, path)
	case proto.Request_Which_segmentTelesSetup:
		return newRequestSegmentTelesSetup(ctrl.SegmentTelesSetup, ts, path)
	case proto.Request_Which_segmentTelesRenewal:
		return newRequestSegmentTelesSetup(ctrl.SegmentTelesRenewal, ts, path)
	case proto.Request_Which_segmentTeardown:
		return newRequestSegmentTeardown(ctrl.SegmentTeardown, ts, path)
	case proto.Request_Which_segmentIndexConfirmation:
		return newRequestSegmentIndexConfirmation(ctrl.SegmentIndexConfirmation, ts, path)
	case proto.Request_Which_segmentCleanup:
		return newRequestSegmentCleanup(ctrl.SegmentCleanup, ts, path)
	case proto.Request_Which_e2eSetup:
		return newRequestE2ESetup(ctrl.E2ESetup, ts, path)
	case proto.Request_Which_e2eRenewal:
		return newRequestE2ESetup(ctrl.E2ERenewal, ts, path)
	case proto.Request_Which_e2eCleanup:
		return newRequestE2ECleanup(ctrl.E2ECleanup, ts, path)
	default:
		return nil, serrors.New("invalid ctrl message", "ctrl", ctrl.Which.String())
	}
}

func newResponseFromCtrl(ctrl *colibri_mgmt.Response, ts time.Time, path base.ColibriPath) (
	base.MessageWithPath, error) {

	if ctrl == nil {
		return nil, serrors.New("nil ctrl message", "type", "Request")
	}
	switch ctrl.Which {
	case proto.Response_Which_segmentSetup:
		return newResponseSegmentSetup(ctrl.SegmentSetup, ctrl, ts, path)
	case proto.Response_Which_segmentRenewal:
		return newResponseSegmentSetup(ctrl.SegmentRenewal, ctrl, ts, path)
	case proto.Response_Which_segmentTeardown:
		return newResponseSegmentTeardown(ctrl.SegmentTeardown, ctrl, ts, path)
	case proto.Response_Which_segmentIndexConfirmation:
		return newResponseSegmentIndexConfirmation(ctrl.SegmentIndexConfirmation, ctrl, ts, path)
	case proto.Response_Which_segmentCleanup:
		return newResponseSegmentCleanup(ctrl.SegmentCleanup, ctrl, ts, path)
	case proto.Response_Which_e2eSetup:
		return newResponseE2ESetup(ctrl.E2ESetup, ctrl, ts, path)
	case proto.Response_Which_e2eRenewal:
		return newResponseE2ESetup(ctrl.E2ERenewal, ctrl, ts, path)
	case proto.Response_Which_e2eCleanup:
		return newResponseE2EClenaup(ctrl.E2ECleanup, ctrl, ts, path)
	default:
		return nil, serrors.New("invalid ctrl message", "ctrl", ctrl.Which.String())
	}
}

// newRequestSegmentSetup constructs a SetupReq from its control message counterpart.
// The timestamp comes from the wrapping ColibriRequestPayload,
// and the path from the wrapping packet.
func newRequestSegmentSetup(ctrl *colibri_mgmt.SegmentSetup, ts time.Time,
	path base.ColibriPath) (*segment.SetupReq, error) {

	id, err := NewSegmentIDFromCtrl(ctrl.Base.ID)
	if err != nil {
		return nil, serrors.WrapStr("cannot convert id", err)
	}
	r, err := segment.NewRequest(ts, id, reservation.IndexNumber(ctrl.Base.Index), path)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct segment setup request", err)
	}
	inF, err := reservation.InfoFieldFromRaw(ctrl.InfoField)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct info field from raw", err)
	}
	if inF == nil {
		return nil, serrors.New("empty info field", "raw", hex.EncodeToString(ctrl.InfoField))
	}
	s := &segment.SetupReq{
		Request:    *r,
		InfoField:  *inF,
		MinBW:      reservation.BWCls(ctrl.MinBW),
		MaxBW:      reservation.BWCls(ctrl.MaxBW),
		SplitCls:   reservation.SplitCls(ctrl.SplitCls),
		AllocTrail: make(reservation.AllocationBeads, len(ctrl.AllocationTrail)),
		PathProps: reservation.NewPathEndProps(ctrl.StartProps.Local, ctrl.StartProps.Transfer,
			ctrl.EndProps.Local, ctrl.EndProps.Transfer),
	}
	for i, ab := range ctrl.AllocationTrail {
		s.AllocTrail[i] = reservation.AllocationBead{
			AllocBW: reservation.BWCls(ab.AllocBW),
			MaxBW:   reservation.BWCls(ab.MaxBW),
		}
	}
	return s, nil
}

// NewTelesRequestFromCtrlMsg constucts the app type from its control message counterpart.
func newRequestSegmentTelesSetup(ctrl *colibri_mgmt.SegmentTelesSetup, ts time.Time,
	path base.ColibriPath) (*segment.SetupTelesReq, error) {

	if ctrl.BaseID == nil || ctrl.Setup == nil {
		return nil, serrors.New("illegal ctrl telescopic setup received", "base_id", ctrl.BaseID,
			"segment_setup", ctrl.Setup)
	}
	baseReq, err := newRequestSegmentSetup(ctrl.Setup, ts, path)
	if err != nil {
		return nil, serrors.WrapStr("failed to construct base request", err)
	}
	s := &segment.SetupTelesReq{
		SetupReq: *baseReq,
	}
	id, err := reservation.SegmentIDFromRawBuffers(ctrl.BaseID.ASID, ctrl.BaseID.Suffix)
	if err != nil {
		return nil, err
	}
	s.BaseID = *id
	return s, nil
}

func newRequestSegmentTeardown(ctrl *colibri_mgmt.SegmentTeardownReq, ts time.Time,
	path base.ColibriPath) (*segment.TeardownReq, error) {

	id, err := NewSegmentIDFromCtrl(ctrl.Base.ID)
	if err != nil {
		return nil, serrors.WrapStr("cannot convert id", err)
	}
	r, err := segment.NewRequest(ts, id, reservation.IndexNumber(ctrl.Base.Index), path)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct segment teardown request", err)
	}
	return &segment.TeardownReq{
		Request: *r,
	}, nil
}

func newRequestSegmentIndexConfirmation(ctrl *colibri_mgmt.SegmentIndexConfirmation, ts time.Time,
	path base.ColibriPath) (*segment.IndexConfirmationReq, error) {

	id, err := NewSegmentIDFromCtrl(ctrl.Base.ID)
	if err != nil {
		return nil, serrors.WrapStr("cannot convert id", err)
	}
	r, err := segment.NewRequest(ts, id, reservation.IndexNumber(ctrl.Base.Index), path)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct segment idx confirmation request", err)
	}
	st, err := NewIndexStateFromCtrl(ctrl.State)
	if err != nil {
		return nil, err
	}
	return &segment.IndexConfirmationReq{
		Request: *r,
		State:   st,
	}, nil
}

func newRequestSegmentCleanup(ctrl *colibri_mgmt.SegmentCleanup, ts time.Time,
	path base.ColibriPath) (*segment.CleanupReq, error) {

	id, err := NewSegmentIDFromCtrl(ctrl.Base.ID)
	if err != nil {
		return nil, serrors.WrapStr("cannot convert id", err)
	}
	r, err := segment.NewRequest(ts, id, reservation.IndexNumber(ctrl.Base.Index), path)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct segment cleanup request", err)
	}
	return &segment.CleanupReq{
		Request: *r,
	}, nil
}

func newRequestE2ESetup(ctrl *colibri_mgmt.E2ESetup, ts time.Time,
	path base.ColibriPath) (base.MessageWithPath, error) {

	id, err := NewE2EIDFromCtrl(ctrl.Base.ID)
	if err != nil {
		return nil, serrors.WrapStr("cannot convert id", err)
	}
	r, err := e2e.NewRequest(ts, id, reservation.IndexNumber(ctrl.Base.Index), path)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct e2e setup request", err)
	}
	segmentIDs := make([]reservation.SegmentID, len(ctrl.SegmentRsvs))
	for i := range ctrl.SegmentRsvs {
		id, err := NewSegmentIDFromCtrl(&ctrl.SegmentRsvs[i])
		if err != nil {
			return nil, serrors.WrapStr("cannot translate segment id in e2e setup", err,
				"asid", hex.EncodeToString(ctrl.SegmentRsvs[i].ASID),
				"suffix", hex.EncodeToString(ctrl.SegmentRsvs[i].Suffix))
		}
		segmentIDs[i] = *id
	}
	allocTrail := make([]reservation.BWCls, len(ctrl.AllocationTrail))
	for i := range ctrl.AllocationTrail {
		allocTrail[i] = reservation.BWCls(ctrl.AllocationTrail[i])
	}
	setup, err := e2e.NewSetupRequest(r, segmentIDs, ctrl.SegmentRsvASCount,
		reservation.BWCls(ctrl.RequestedBW), allocTrail)
	if err != nil {
		return nil, serrors.WrapStr("cannot contruct e2e setup request", err)
	}
	switch ctrl.Which {
	case proto.E2ESetupReqData_Which_success:
		tok, err := reservation.TokenFromRaw(ctrl.Success.Token)
		if err != nil {
			return nil, serrors.WrapStr("cannot construct e2e setup success request", err)
		}
		return &e2e.SetupReqSuccess{
			SetupReq: *setup,
			Token:    *tok,
		}, nil
	case proto.E2ESetupReqData_Which_failure:
		return &e2e.SetupReqFailure{
			SetupReq:  *setup,
			ErrorCode: ctrl.Failure.ErrorCode,
		}, nil
	default:
		return nil, serrors.New("invalid ctrl message", "ctrl", ctrl.Which.String())
	}
}

func newRequestE2ECleanup(ctrl *colibri_mgmt.E2ECleanup, ts time.Time,
	path base.ColibriPath) (*e2e.CleanupReq, error) {

	id, err := NewE2EIDFromCtrl(ctrl.Base.ID)
	if err != nil {
		return nil, serrors.WrapStr("cannot convert id", err)
	}
	r, err := e2e.NewRequest(ts, id, reservation.IndexNumber(ctrl.Base.Index), path)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct e2e cleanup request", err)
	}
	return &e2e.CleanupReq{
		Request: *r,
	}, nil
}

// the failedHop parameter won't be used if the response is successful.
func newResponseSegmentSetup(ctrl *colibri_mgmt.SegmentSetupRes, resp *colibri_mgmt.Response,
	ts time.Time, path base.ColibriPath) (base.MessageWithPath, error) {

	id, err := NewSegmentIDFromCtrl(ctrl.Base.ID)
	if err != nil {
		return nil, serrors.WrapStr("cannot convert id", err)
	}
	r, err := segment.NewResponse(ts, id, reservation.IndexNumber(ctrl.Base.Index), path,
		resp.Accepted, resp.FailedHop)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct segment setup response", err)
	}
	switch ctrl.Which {
	case proto.SegmentSetupResData_Which_token:
		tok, err := reservation.TokenFromRaw(ctrl.Token)
		if err != nil {
			return nil, serrors.WrapStr("cannot parse token", err)
		}
		return &segment.ResponseSetupSuccess{
			Response: *r,
			Token:    *tok,
		}, nil
	case proto.SegmentSetupResData_Which_failure:
		failedSetup, err := newRequestSegmentSetup(ctrl.Failure, ts, path)
		if err != nil {
			return nil, serrors.WrapStr("cannot parse failed setup", err)
		}
		return &segment.ResponseSetupFailure{
			Response:    *r,
			FailedSetup: failedSetup,
		}, nil
	default:
		return nil, serrors.New("invalid ctrl message", "ctrl", ctrl.Which.String())
	}
}

func newResponseSegmentTeardown(ctrl *colibri_mgmt.SegmentTeardownRes, resp *colibri_mgmt.Response,
	ts time.Time, path base.ColibriPath) (base.MessageWithPath, error) {

	id, err := NewSegmentIDFromCtrl(ctrl.Base.ID)
	if err != nil {
		return nil, serrors.WrapStr("cannot convert id", err)
	}
	r, err := segment.NewResponse(ts, id, reservation.IndexNumber(ctrl.Base.Index), path,
		resp.Accepted, resp.FailedHop)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct segment setup response", err)
	}
	if resp.Accepted {
		return &segment.ResponseTeardownSuccess{
			Response: *r,
		}, nil
	} else {
		return &segment.ResponseTeardownFailure{
			Response:  *r,
			ErrorCode: ctrl.ErrorCode,
		}, nil
	}
}

func newResponseSegmentIndexConfirmation(ctrl *colibri_mgmt.SegmentIndexConfirmationRes,
	resp *colibri_mgmt.Response, ts time.Time,
	path base.ColibriPath) (base.MessageWithPath, error) {

	id, err := NewSegmentIDFromCtrl(ctrl.Base.ID)
	if err != nil {
		return nil, serrors.WrapStr("cannot convert id", err)
	}
	r, err := segment.NewResponse(ts, id, reservation.IndexNumber(ctrl.Base.Index), path,
		resp.Accepted, resp.FailedHop)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct segment setup response", err)
	}
	if resp.Accepted {
		return &segment.ResponseIndexConfirmationSuccess{
			Response: *r,
		}, nil
	} else {
		return &segment.ResponseIndexConfirmationFailure{
			Response:  *r,
			ErrorCode: ctrl.ErrorCode,
		}, nil
	}
}

func newResponseSegmentCleanup(ctrl *colibri_mgmt.SegmentCleanupRes, resp *colibri_mgmt.Response,
	ts time.Time, path base.ColibriPath) (base.MessageWithPath, error) {

	id, err := NewSegmentIDFromCtrl(ctrl.Base.ID)
	if err != nil {
		return nil, serrors.WrapStr("cannot convert id", err)
	}
	r, err := segment.NewResponse(ts, id, reservation.IndexNumber(ctrl.Base.Index), path,
		resp.Accepted, resp.FailedHop)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct segment setup response", err)
	}
	if resp.Accepted {
		return &segment.ResponseCleanupSuccess{
			Response: *r,
		}, nil
	} else {
		return &segment.ResponseCleanupFailure{
			Response:  *r,
			ErrorCode: ctrl.ErrorCode,
		}, nil
	}
}

func newResponseE2ESetup(ctrl *colibri_mgmt.E2ESetupRes, resp *colibri_mgmt.Response,
	ts time.Time, path base.ColibriPath) (base.MessageWithPath, error) {

	id, err := NewE2EIDFromCtrl(ctrl.Base.ID)
	if err != nil {
		return nil, serrors.WrapStr("cannot convert id", err)
	}
	r, err := e2e.NewResponse(ts, id, reservation.IndexNumber(ctrl.Base.Index), path,
		resp.Accepted, resp.FailedHop)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct segment setup response", err)
	}
	switch ctrl.Which {
	case proto.E2ESetupResData_Which_success:
		tok, err := reservation.TokenFromRaw(ctrl.Success.Token)
		if err != nil {
			return nil, serrors.WrapStr("cannot parse token", err)
		}
		return &e2e.ResponseSetupSuccess{
			Response: *r,
			Token:    *tok,
		}, nil
	case proto.E2ESetupResData_Which_failure:
		maxBWs := make([]reservation.BWCls, len(ctrl.Failure.AllocationTrail))
		for i := range ctrl.Failure.AllocationTrail {
			maxBWs[i] = reservation.BWCls(ctrl.Failure.AllocationTrail[i])
		}
		return &e2e.ResponseSetupFailure{
			Response:  *r,
			ErrorCode: ctrl.Failure.ErrorCode,
			MaxBWs:    maxBWs,
		}, nil
	default:
		return nil, serrors.New("invalid ctrl message", "ctrl", ctrl.Which.String())
	}
}

func newResponseE2EClenaup(ctrl *colibri_mgmt.E2ECleanupRes, resp *colibri_mgmt.Response,
	ts time.Time, path base.ColibriPath) (base.MessageWithPath, error) {

	id, err := NewE2EIDFromCtrl(ctrl.Base.ID)
	if err != nil {
		return nil, serrors.WrapStr("cannot convert id", err)
	}
	r, err := e2e.NewResponse(ts, id, reservation.IndexNumber(ctrl.Base.Index), path,
		resp.Accepted, resp.FailedHop)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct segment setup response", err)
	}
	if resp.Accepted {
		return &e2e.ResponseCleanupSuccess{
			Response: *r,
		}, nil
	} else {
		return &e2e.ResponseCleanupFailure{
			Response:  *r,
			ErrorCode: ctrl.ErrorCode,
		}, nil
	}
}
