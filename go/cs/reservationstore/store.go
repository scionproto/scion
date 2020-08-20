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

package reservationstore

import (
	"context"
	"time"

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/cs/reservation/e2e"
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/cs/reservation/segment/admission"
	"github.com/scionproto/scion/go/cs/reservationstorage"
	"github.com/scionproto/scion/go/cs/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Store is the reservation store.
type Store struct {
	db       backend.DB         // aka reservation map
	admitter admission.Admitter // the chosen admission entity
}

var _ reservationstorage.Store = (*Store)(nil)

// NewStore creates a new reservation store.
func NewStore(db backend.DB, admitter admission.Admitter) *Store {
	return &Store{
		db:       db,
		admitter: admitter,
	}
}

// AdmitSegmentReservation receives a setup/renewal request to admit a segment reservation.
// It is expected that this AS is not the reservation initiator.
func (s *Store) AdmitSegmentReservation(ctx context.Context, req *segment.SetupReq) (
	base.MessageWithPath, error) {

	if err := s.validateAuthenticators(&req.RequestMetadata); err != nil {
		return nil, serrors.WrapStr("error validating request", err, "id", req.ID)
	}
	if req.IndexOfCurrentHop() != len(req.AllocTrail) {
		return nil, serrors.New("inconsistent number of hops",
			"len_alloctrail", len(req.AllocTrail), "hf_count", req.IndexOfCurrentHop())
	}
	response, err := s.prepareFailureSegmentResp(&req.Request)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct response", err, "id", req.ID)
	}
	failedResponse := &segment.ResponseSetupFailure{
		Response:    *response,
		FailedSetup: req,
	}
	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot create transaction", err,
			"id", req.ID)
	}
	defer tx.Rollback()

	rsv, err := tx.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot obtain segment reservation", err,
			"id", req.ID)
	}

	var index *segment.Index
	if rsv != nil {
		// renewal, ensure index is not used
		index = rsv.Index(req.InfoField.Idx)
		if index != nil {
			return failedResponse, serrors.New("index from setup already in use",
				"idx", req.InfoField.Idx, "id", req.ID)
		}
	} else {
		// setup, create reservation and an index
		rsv = segment.NewReservation()
		rsv.ID = req.ID
		err = tx.NewSegmentRsv(ctx, rsv)
		if err != nil {
			return failedResponse, serrors.WrapStr(
				"unable to create a new segment reservation in db", err,
				"id", req.ID)
		}
	}
	req.Reservation = rsv
	tok := &reservation.Token{InfoField: req.InfoField}
	idx, err := rsv.NewIndexFromToken(tok, req.MinBW, req.MaxBW)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot create index from token", err,
			"id", req.ID)
	}
	index = rsv.Index(idx)

	// checkpath type compatibility with end properties
	if err := rsv.PathEndProps.ValidateWithPathType(rsv.PathType); err != nil {
		return failedResponse, serrors.WrapStr("error validating end props and path type", err,
			"id", req.ID)
	}
	// compute admission max BW
	// TODO(juagargi) use the transaction also in the admitter
	err = s.admitter.AdmitRsv(ctx, req)
	if err != nil {
		return failedResponse, serrors.WrapStr("not admitted", err)
	}
	// admitted; the request contains already the value inside the "allocation beads" of the rsv
	index.AllocBW = req.AllocTrail[len(req.AllocTrail)-1].AllocBW
	if err = tx.PersistSegmentRsv(ctx, rsv); err != nil {
		return failedResponse, serrors.WrapStr("cannot persist segment reservation", err,
			"id", req.ID)
	}
	if err := tx.Commit(); err != nil {
		return failedResponse, serrors.WrapStr("cannot commit transaction", err, "id", req.ID)
	}
	var msg base.MessageWithPath
	if req.IsLastAS() {
		// TODO(juagargi) update token here
		msg = &segment.ResponseSetupSuccess{
			Response: *morphSegmentResponseToSuccess(response),
			Token:    *index.Token,
		}
	} else {
		msg = req
	}
	// TODO(juagargi) refactor function
	return msg, nil
}

// ConfirmSegmentReservation changes the state of an index from temporary to confirmed.
func (s *Store) ConfirmSegmentReservation(ctx context.Context, req *segment.IndexConfirmationReq) (
	base.MessageWithPath, error) {

	if err := s.validateAuthenticators(&req.RequestMetadata); err != nil {
		return nil, serrors.WrapStr("error validating request", err, "id", req.ID)
	}
	response, err := s.prepareFailureSegmentResp(&req.Request)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct response", err, "id", req.ID)
	}
	failedResponse := &segment.ResponseIndexConfirmationFailure{
		Response:  *response,
		ErrorCode: 1, // TODO(juagargi) specify error codes for every response
	}
	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot create transaction", err, "id", req.ID)
	}
	defer tx.Rollback()

	rsv, err := tx.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot obtain segment reservation", err,
			"id", req.ID)
	}
	if err := rsv.SetIndexConfirmed(req.Index); err != nil {
		return failedResponse, serrors.WrapStr("cannot set index to confirmed", err,
			"id", req.ID)
	}
	if err = tx.PersistSegmentRsv(ctx, rsv); err != nil {
		return failedResponse, serrors.WrapStr("cannot persist segment reservation", err,
			"id", req.ID)
	}
	if err := tx.Commit(); err != nil {
		return failedResponse, serrors.WrapStr("cannot commit transaction", err,
			"id", req.ID)
	}
	var msg base.MessageWithPath
	if req.IsLastAS() {
		msg = &segment.ResponseIndexConfirmationSuccess{
			Response: *morphSegmentResponseToSuccess(response),
		}
	} else {
		msg = req
	}

	return msg, nil
}

// CleanupSegmentReservation deletes an index from a segment reservation.
func (s *Store) CleanupSegmentReservation(ctx context.Context, req *segment.CleanupReq) (
	base.MessageWithPath, error) {

	if err := s.validateAuthenticators(&req.RequestMetadata); err != nil {
		return nil, serrors.WrapStr("error validating request", err, "id", req.ID)
	}
	response, err := s.prepareFailureSegmentResp(&req.Request)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct response", err, "id", req.ID)
	}
	failedResponse := &segment.ResponseCleanupFailure{
		Response:  *response,
		ErrorCode: 1,
	}
	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot create transaction", err, "id", req.ID)
	}
	defer tx.Rollback()

	rsv, err := tx.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot obtain segment reservation", err,
			"id", req.ID)
	}
	if err := rsv.RemoveIndex(req.Index); err != nil {
		return failedResponse, serrors.WrapStr("cannot delete segment reservation index", err,
			"id", req.ID, "index", req.Index)
	}
	if err = tx.PersistSegmentRsv(ctx, rsv); err != nil {
		return failedResponse, serrors.WrapStr("cannot persist segment reservation", err,
			"id", req.ID)
	}
	if err := tx.Commit(); err != nil {
		return failedResponse, serrors.WrapStr("cannot commit transaction", err,
			"id", req.ID)
	}
	var msg base.MessageWithPath
	if req.IsLastAS() {
		msg = &segment.ResponseCleanupSuccess{
			Response: *morphSegmentResponseToSuccess(response),
		}
	} else {
		msg = req
	}

	return msg, nil
}

// TearDownSegmentReservation removes a whole segment reservation.
func (s *Store) TearDownSegmentReservation(ctx context.Context, req *segment.TeardownReq) (
	base.MessageWithPath, error) {

	if err := s.validateAuthenticators(&req.RequestMetadata); err != nil {
		return nil, serrors.WrapStr("error validating request", err, "id", req.ID)
	}
	response, err := s.prepareFailureSegmentResp(&req.Request)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct response", err, "id", req.ID)
	}
	failedResponse := &segment.ResponseTeardownFailure{
		Response:  *response,
		ErrorCode: 1,
	}
	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot create transaction", err, "id", req.ID)
	}
	defer tx.Rollback()

	if err := tx.DeleteSegmentRsv(ctx, &req.ID); err != nil {
		return failedResponse, serrors.WrapStr("cannot teardown reservation", err,
			"id", req.ID)
	}
	if err := tx.Commit(); err != nil {
		return failedResponse, serrors.WrapStr("cannot commit transaction", err,
			"id", req.ID)
	}
	var msg base.MessageWithPath
	if req.IsLastAS() {
		msg = &segment.ResponseTeardownSuccess{
			Response: *morphSegmentResponseToSuccess(response),
		}
	} else {
		msg = req
	}

	return msg, nil
}

// AdmitE2EReservation will atempt to admit an e2e reservation.
func (s *Store) AdmitE2EReservation(ctx context.Context, req *e2e.SetupReq) (
	base.MessageWithPath, error) {

	return nil, nil
}

// CleanupE2EReservation will remove an index from an e2e reservation.
func (s *Store) CleanupE2EReservation(ctx context.Context, req *e2e.CleanupReq) (
	base.MessageWithPath, error) {

	if err := s.validateAuthenticators(&req.RequestMetadata); err != nil {
		return nil, serrors.WrapStr("error validating request", err, "id", req.ID)
	}
	response, err := s.prepareFailureE2EResp(&req.Request)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct response", err, "id", req.ID)
	}
	failedResponse := &e2e.ResponseCleanupFailure{
		Response:  *response,
		ErrorCode: 1,
	}
	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot create transaction", err, "id", req.ID)
	}
	defer tx.Rollback()

	rsv, err := tx.GetE2ERsvFromID(ctx, &req.ID)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot obtain e2e reservation", err,
			"id", req.ID)
	}
	if err := rsv.RemoveIndex(req.Index); err != nil {
		return failedResponse, serrors.WrapStr("cannot delete e2e reservation index", err,
			"id", req.ID, "index", req.Index)
	}
	if err := tx.PersistE2ERsv(ctx, rsv); err != nil {
		return failedResponse, serrors.WrapStr("cannot persist e2e reservation", err,
			"id", req.ID)
	}
	if err := tx.Commit(); err != nil {
		return failedResponse, serrors.WrapStr("cannot commit transaction", err,
			"id", req.ID)
	}
	var msg base.MessageWithPath
	if req.IsLastAS() {
		msg = &e2e.ResponseCleanupSuccess{
			Response: *morphE2EResponseToSuccess(response),
		}
	} else {
		msg = req
	}

	return msg, nil
}

// DeleteExpiredIndices will just call the DB's method to delete the expired indices.
func (s *Store) DeleteExpiredIndices(ctx context.Context) (int, error) {
	return s.db.DeleteExpiredIndices(ctx, time.Now())
}

// validateAuthenticators checks that the authenticators are correct.
func (s *Store) validateAuthenticators(req *base.RequestMetadata) error {
	// TODO(juagargi) validate request
	// DRKey authentication of request (will be left undone for later)
	return nil
}

// prepareFailureSegmentResp will create a failure segment response, which
// is sent in the reverse path that the request had.
func (s *Store) prepareFailureSegmentResp(req *segment.Request) (*segment.Response, error) {
	revPath := req.Path().Copy()
	if err := revPath.Reverse(); err != nil {
		return nil, serrors.WrapStr("cannot reverse path for response", err)
	}
	response, err := segment.NewResponse(time.Now(), &req.ID, req.Index, revPath,
		false, uint8(req.IndexOfCurrentHop()))
	if err != nil {
		return nil, serrors.WrapStr("cannot construct segment response", err)
	}
	return response, nil
}

// prepareFailureE2EResp will create a failure e2e response, which
// is sent in the reverse path that the request had.
func (s *Store) prepareFailureE2EResp(req *e2e.Request) (*e2e.Response, error) {
	revPath := req.Path().Copy()
	if err := revPath.Reverse(); err != nil {
		return nil, serrors.WrapStr("cannot reverse path for response", err)
	}
	response, err := e2e.NewResponse(time.Now(), &req.ID, req.Index, revPath,
		false, uint8(req.IndexOfCurrentHop()))
	if err != nil {
		return nil, serrors.WrapStr("cannot construct e2e response", err)
	}
	return response, nil
}

func morphSegmentResponseToSuccess(resp *segment.Response) *segment.Response {
	resp.Accepted = true
	resp.FailedHop = 0
	return resp
}

func morphE2EResponseToSuccess(resp *e2e.Response) *e2e.Response {
	resp.Accepted = true
	resp.FailedHop = 0
	return resp
}
