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
	"math"
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
	if req.Path().IndexOfCurrentHop() != len(req.AllocTrail) {
		return nil, serrors.New("inconsistent number of hops",
			"len_alloctrail", len(req.AllocTrail), "hf_count", req.Path().IndexOfCurrentHop())
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

	if rsv != nil {
		// renewal, ensure index is not used
		index := rsv.Index(req.InfoField.Idx)
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
	index := rsv.Index(idx)

	// checkpath type compatibility with end properties
	if err := rsv.PathEndProps.ValidateWithPathType(rsv.PathType); err != nil {
		return failedResponse, serrors.WrapStr("error validating end props and path type", err,
			"id", req.ID)
	}
	// compute admission max BW
	// TODO(juagargi) use the transaction also in the admitter
	err = s.admitter.AdmitRsv(ctx, req)
	if err != nil {
		return failedResponse, serrors.WrapStr("segment not admitted", err, "id", req.ID,
			"index", req.Index)
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

	if req.IsLastAS() {
		// TODO(juagargi) update token here
		return &segment.ResponseSetupSuccess{
			Response: *morphSegmentResponseToSuccess(response),
			Token:    *index.Token,
		}, nil
	}
	// TODO(juagargi) refactor function
	return req, nil
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
	if req.IsLastAS() {
		return &segment.ResponseIndexConfirmationSuccess{
			Response: *morphSegmentResponseToSuccess(response),
		}, nil
	}
	return req, nil
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

	if req.IsLastAS() {
		return &segment.ResponseCleanupSuccess{
			Response: *morphSegmentResponseToSuccess(response),
		}, nil
	}
	return req, nil
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

	if req.IsLastAS() {
		return &segment.ResponseTeardownSuccess{
			Response: *morphSegmentResponseToSuccess(response),
		}, nil
	}
	return req, nil
}

// AdmitE2EReservation will atempt to admit an e2e reservation.
func (s *Store) AdmitE2EReservation(ctx context.Context, request e2e.SetupRequest) (
	base.MessageWithPath, error) {

	req := request.GetCommonSetupReq()
	if err := s.validateAuthenticators(&req.RequestMetadata); err != nil {
		return nil, serrors.WrapStr("error validating e2e request", err, "id", req.ID)
	}

	response, err := s.prepareFailureE2EResp(&req.Request)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct response", err, "id", req.ID)
	}
	var failedResponse base.MessageWithPath
	failedResponse = &e2e.ResponseSetupFailure{
		Response:  *response,
		ErrorCode: 1,
		MaxBWs:    req.AllocationTrail,
	}

	// sanity check: all successful requests are SetupReqSuccess. Failed ones are SetupReqFailure.
	if request.IsSuccessful() {
		if _, ok := request.(*e2e.SetupReqSuccess); !ok {
			return failedResponse, serrors.New("logic error, successful request can be casted")
		}
	} else {
		if _, ok := request.(*e2e.SetupReqFailure); !ok {
			return failedResponse, serrors.New("logic error, failed request can be casted")
		}
	}

	if len(req.SegmentRsvs) == 0 || len(req.SegmentRsvs) > 3 {
		return failedResponse, serrors.New("invalid number of segment reservations for an e2e one",
			"count", len(req.SegmentRsvs))
	}

	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot create transaction", err,
			"id", req.ID)
	}
	defer tx.Rollback()

	rsv, err := tx.GetE2ERsvFromID(ctx, &req.ID)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot obtain e2e reservation", err,
			"id", req.ID)
	}

	segRsvIDs := req.SegmentRsvIDsForThisAS()
	if rsv != nil {
		// renewal
		if index := rsv.Index(req.Index); index != nil {
			return failedResponse, serrors.New("already existing e2e index", "id", req.ID,
				"idx", req.Index)
		}
	} else {
		// new setup
		rsv = &e2e.Reservation{
			ID:                  req.ID,
			SegmentReservations: make([]*segment.Reservation, len(segRsvIDs)),
		}
		for i, id := range segRsvIDs {
			r, err := tx.GetSegmentRsvFromID(ctx, &id)
			if err != nil {
				return failedResponse, serrors.WrapStr("cannot get segment rsv for e2e admission",
					err, "e2e_id", req.ID, "seg_id", id)
			}
			rsv.SegmentReservations[i] = r
		}
	}
	if len(rsv.SegmentReservations) == 0 {
		return failedResponse, serrors.New("there is no segment rsv. associated to this e2e rsv.",
			"id", req.ID, "idx", req.Index)
	}

	idx, err := rsv.NewIndex(req.Timestamp)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot create index in e2e admission", err,
			"e2e_id", req.ID)
	}
	index := rsv.Index(idx)
	index.AllocBW = req.RequestedBW
	if request.IsSuccessful() {
		index.Token = &request.(*e2e.SetupReqSuccess).Token
	}

	free, err := freeInSegRsv(ctx, tx, rsv.SegmentReservations[0])
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot compute free bw for e2e admission", err,
			"e2e_id", rsv.ID)
	}
	free = free + rsv.AllocResv() // don't count this E2E request in the used BW

	if req.Transfer() {
		// this AS must stitch two segment rsvs. according to the request
		if len(segRsvIDs) == 1 {
			return failedResponse, serrors.New("e2e setup request with transfer inconsistent",
				"e2e_id", req.ID, "req_sgmt_rsvs_count", req.SegmentRsvASCount,
				"trail_len", len(req.AllocationTrail))
		}
		freeOutgoing, err := freeAfterTransfer(ctx, tx, rsv)
		if err != nil {
			return failedResponse, serrors.WrapStr("cannot compute transfer", err, "id", req.ID)
		}
		freeOutgoing += rsv.AllocResv() // do not count this rsv's BW
		if free > freeOutgoing {
			free = freeOutgoing
		}
	}

	if !request.IsSuccessful() || req.RequestedBW.ToKbps() > free {
		maxWillingToAlloc := reservation.BWClsFromBW(free)
		if req.Location() == e2e.Destination {
			asAResponse := failedResponse.(*e2e.ResponseSetupFailure)
			asAResponse.MaxBWs = append(asAResponse.MaxBWs, maxWillingToAlloc)
		} else {
			asARequest := &e2e.SetupReqFailure{
				SetupReq:  *req,
				ErrorCode: 1,
			}
			asARequest.AllocationTrail = append(asARequest.AllocationTrail, maxWillingToAlloc)
			failedResponse = asARequest
		}
		return failedResponse, serrors.WrapStr("e2e not admitted", err, "id", req.ID,
			"index", req.Index)
	}

	// admitted so far
	// TODO(juagargi) update token here
	if err := tx.PersistE2ERsv(ctx, rsv); err != nil {
		return failedResponse, serrors.WrapStr("cannot persist e2e reservation", err,
			"id", req.ID)
	}

	if err := tx.Commit(); err != nil {
		return failedResponse, serrors.WrapStr("cannot commit transaction", err, "id", req.ID)
	}

	var msg base.MessageWithPath
	if req.Location() == e2e.Destination {
		asAResponse := failedResponse.(*e2e.ResponseSetupFailure)
		msg = &e2e.ResponseSetupSuccess{
			Response: *morphE2EResponseToSuccess(&asAResponse.Response),
			Token:    *index.Token,
		}
	} else {
		msg = &e2e.SetupReqSuccess{
			SetupReq: *req,
			Token:    *index.Token,
		}
	}
	return msg, nil
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

	if req.IsLastAS() {
		return &e2e.ResponseCleanupSuccess{
			Response: *morphE2EResponseToSuccess(response),
		}, nil
	}

	return req, nil
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
		false, uint8(req.Path().IndexOfCurrentHop()))
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
		false, uint8(req.Path().IndexOfCurrentHop()))
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

func sumAllBW(rsvs []*e2e.Reservation) uint64 {
	var accum uint64
	for _, r := range rsvs {
		accum += r.AllocResv()
	}
	return accum
}

func freeInSegRsv(ctx context.Context, tx backend.Transaction, segRsv *segment.Reservation) (
	uint64, error) {

	rsvs, err := tx.GetE2ERsvsOnSegRsv(ctx, &segRsv.ID)
	if err != nil {
		return 0, serrors.WrapStr("cannot obtain e2e reservations to compute free bw",
			err, "segment_id", segRsv.ID)
	}
	free := float64(segRsv.ActiveIndex().AllocBW.ToKbps())*float64(segRsv.TrafficSplit) -
		float64(sumAllBW(rsvs))
	return uint64(free), nil
}

// max bw in egress interface of the transfer AS
func freeAfterTransfer(ctx context.Context, tx backend.Transaction, rsv *e2e.Reservation) (
	uint64, error) {

	seg1 := rsv.SegmentReservations[0]
	seg2 := rsv.SegmentReservations[1]
	if seg1.PathType == reservation.CorePath && seg2.PathType == reservation.DownPath {
		// as if no transfer
		return math.MaxUint64, nil
	}
	// get all seg rsvs with this AS as destination, AND transfer flag set
	rsvs, err := tx.GetAllSegmentRsvs(ctx)
	if err != nil {
		return 0, err
	}
	var total uint64
	for _, r := range rsvs {
		if r.Egress == 0 && r.PathEndProps&reservation.EndTransfer != 0 {
			total += r.ActiveIndex().AllocBW.ToKbps()
		}
	}
	ratio := float64(seg1.ActiveIndex().AllocBW.ToKbps()) / float64(total)
	// effectiveE2eTraffic is the minimum BW that e2e rsvs can use
	effectiveE2eTraffic := float64(seg2.ActiveIndex().AllocBW.ToKbps()) * ratio
	e2es, err := tx.GetE2ERsvsOnSegRsv(ctx, &seg2.ID)
	if err != nil {
		return 0, err
	}
	total = sumAllBW(e2es)
	// the available BW for this e2e rsv is the effective minus the already used
	return uint64(effectiveE2eTraffic) - total, nil
}
