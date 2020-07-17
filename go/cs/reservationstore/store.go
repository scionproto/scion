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
	segment.Response, error) {

	// validate request:
	// DRKey authentication of request (will be left undone for later)
	failedResponse := &segment.ResponseSetupFailure{
		// TODO(juagargi) should we get the hop number from the spath instead?
		FailedHop: uint8(len(req.AllocTrail)),
	}
	rsv, err := s.db.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot obtain segment reservation", err)
	}
	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot create transaction", err)
	}
	defer tx.Rollback()

	var index *segment.Index
	if rsv != nil {
		// renewal, ensure index is not used
		index = rsv.Index(req.InfoField.Idx)
		if index != nil {
			return failedResponse, serrors.New("index from setup already in use",
				"idx", req.InfoField.Idx)
		}
	} else {
		// setup, create reservation and an index
		rsv = segment.NewReservation()
		rsv.ID = req.ID
		err = tx.NewSegmentRsv(ctx, rsv)
		if err != nil {
			return failedResponse, serrors.WrapStr(
				"unable to create a new segment reservation in db", err)
		}
	}
	req.Reservation = rsv
	tok := &reservation.Token{InfoField: req.InfoField}
	idx, err := rsv.NewIndexFromToken(tok, req.MinBW, req.MaxBW)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot create index from token", err)
	}
	index = rsv.Index(idx)

	// checkpath type compatibility with end properties
	if err := rsv.PathEndProps.ValidateWithPathType(rsv.PathType); err != nil {
		return failedResponse, serrors.WrapStr("error validating end props and path type", err)
	}
	// compute admission max BW

	// if failure:
	if 5%5 != 0 {
		return failedResponse, nil
	}

	// if success:
	err = tx.PersistSegmentRsv(ctx, rsv)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot persist segment reservation", err)
	}
	if err := tx.Commit(); err != nil {
		return failedResponse, serrors.WrapStr("cannot commit tranaction", err)
	}
	// - send request to next hop, or create reply
	return nil, nil
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
