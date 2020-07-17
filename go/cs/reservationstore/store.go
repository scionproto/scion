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
	"github.com/scionproto/scion/go/cs/reservationstorage"
	"github.com/scionproto/scion/go/cs/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Store is the reservation store.
type Store struct {
	db         backend.DB      // aka reservation map
	capacities base.Capacities // aka capacity matrix
	delta      float64         // fraction of free BW that can be reserved in one request
}

var _ reservationstorage.Store = (*Store)(nil)

// NewStore creates a new reservation store.
func NewStore(db backend.DB) *Store {
	return &Store{
		db: db,
	}
}

// AdmitSegmentReservation receives a setup/renewal request to admit a segment reservation.
// It is expected that this AS is not the reservation initiator.
func (s *Store) AdmitSegmentReservation(ctx context.Context, req segment.SetupReq) (
	base.MessageWithPath, error) {

	// validate request:
	// DRKey authentication of request (will be left undone for later)
	revPath := req.Path().Copy()
	if err := revPath.Reverse(); err != nil {
		return nil, serrors.WrapStr("while admitting a reservation, cannot reverse path", err,
			"id", req.ID)
	}
	revMetadata, err := base.NewRequestMetadata(revPath)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct metadata for reservation packet", err)
	}
	if req.IndexOfCurrentHop() != len(req.AllocTrail) {
		return nil, serrors.New("inconsistent number of hops",
			"len_alloctrail", len(req.AllocTrail), "hf_count", req.IndexOfCurrentHop())
	}
	failedResponse := &segment.ResponseSetupFailure{
		RequestMetadata: *revMetadata,
		FailedHop:       uint8(len(req.AllocTrail)),
	}
	rsv, err := s.db.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot obtain segment reservation", err,
			"id", req.ID)
	}
	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot create transaction", err,
			"id", req.ID)
	}
	defer tx.Rollback()

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
	alloc, err := s.admitSegmentRsv(ctx, req)
	if err != nil {
		// not admitted
		return failedResponse, err
	}
	// admitted; the request contains already the value inside the "allocation beads" of the rsv
	index.AllocBW = alloc
	err = tx.PersistSegmentRsv(ctx, rsv)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot persist segment reservation", err,
			"id", req.ID)
	}
	if err := tx.Commit(); err != nil {
		return failedResponse, serrors.WrapStr("cannot commit transaction", err,
			"id", req.ID)
	}
	var msg base.MessageWithPath
	if req.IsLastAS() {
		// TODO(juagargi) update token here
		msg = &segment.ResponseSetupSuccess{
			RequestMetadata: *revMetadata,
			Token:           *index.Token,
		}
	} else {
		msg = &req
	}
	// TODO(juagargi) refactor function
	return msg, nil
}

// ConfirmSegmentReservation changes the state of an index from temporary to confirmed.
func (s *Store) ConfirmSegmentReservation(ctx context.Context, id reservation.SegmentID,
	idx reservation.IndexNumber) error {

	return nil
}

// CleanupSegmentReservation deletes an index from a segment reservation.
func (s *Store) CleanupSegmentReservation(ctx context.Context, id reservation.SegmentID,
	idx reservation.IndexNumber) error {

	return nil
}

// TearDownSegmentReservation removes a whole segment reservation.
func (s *Store) TearDownSegmentReservation(ctx context.Context, id reservation.SegmentID,
	idx reservation.IndexNumber) error {

	return nil
}

// AdmitE2EReservation will atempt to admit an e2e reservation.
func (s *Store) AdmitE2EReservation(ctx context.Context, req e2e.SetupReq) error {
	return nil
}

// CleanupE2EReservation will remove an index from an e2e reservation.
func (s *Store) CleanupE2EReservation(ctx context.Context, id reservation.E2EID,
	idx reservation.IndexNumber) error {

	return nil
}

// DeleteExpiredIndices will just call the DB's method to delete the expired indices.
func (s *Store) DeleteExpiredIndices(ctx context.Context) (int, error) {
	return s.db.DeleteExpiredIndices(ctx, time.Now())
}

func (s *Store) admitSegmentRsv(ctx context.Context, req segment.SetupReq) (
	reservation.BWCls, error) {

	avail, err := s.availableBW(ctx, req.ID, req.Ingress, req.Egress)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute available bandwidth", err, "segment_id", req.ID)
	}
	ideal, err := s.idealBW(ctx)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute ideal bandwidth", err, "segment_id", req.ID)
	}
	bw := minBW(avail, ideal)

	maxAlloc := reservation.BWClsFromBW(bw)
	if maxAlloc < req.MinBW {
		return 0, serrors.New("admission denied", "maxalloc", maxAlloc, "minbw", req.MinBW,
			"segment_id", req.ID)
	}
	alloc := reservation.MinBWCls(maxAlloc, req.MaxBW)
	bead := reservation.AllocationBead{
		AllocBW: uint8(alloc),
		MaxBW:   uint8(maxAlloc),
	}
	req.AllocTrail = append(req.AllocTrail, bead)
	return alloc, nil
}

func (s *Store) availableBW(ctx context.Context, ID reservation.SegmentID,
	ingress, egress common.IFIDType) (uint64, error) {

	sameIngress, err := s.db.GetSegmentRsvsFromIFPair(ctx, &ingress, nil)
	if err != nil {
		return 0, serrors.WrapStr("cannot get reservations using ingress", err, "ingress", ingress)
	}
	sameEgress, err := s.db.GetSegmentRsvsFromIFPair(ctx, nil, &egress)
	if err != nil {
		return 0, serrors.WrapStr("cannot get reservations using egress", err, "egress", egress)
	}
	bwIngress := sumAllRsvButThis(sameIngress, ID)
	freeIngress := s.capacities.CapacityIngress(ingress) - bwIngress
	bwEgress := sumAllRsvButThis(sameEgress, ID)
	freeEgress := s.capacities.CapacityEgress(egress) - bwEgress
	free := float64(minBW(freeIngress, freeEgress))
	return uint64(free * s.delta), nil
}

func (s *Store) idealBW(ctx context.Context) (uint64, error) {
	tubeRatio := s.tubeRatio(ctx)
	linkRatio := s.linkRatio(ctx)
	_ = tubeRatio
	_ = linkRatio
	return 0, nil
}

func (s *Store) tubeRatio(ctx context.Context) uint64 {
	return 0
}

func (s *Store) linkRatio(ctx context.Context) uint64 {
	return 0
}

func sumAllRsvButThis(rsvs []*segment.Reservation, excludeRsv reservation.SegmentID) uint64 {
	var total uint64
	for _, r := range rsvs {
		if r.ID != excludeRsv {
			total += r.MaxBlockedBW()
		}
	}
	return total
}

func minBW(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
