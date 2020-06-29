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

	"github.com/scionproto/scion/go/cs/reservation/e2e"
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/cs/reservationstorage"
	"github.com/scionproto/scion/go/cs/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
)

// Store is the reservation store.
type Store struct {
	db backend.DB
}

var _ reservationstorage.Store = (*Store)(nil)

// NewStore creates a new reservation store.
func NewStore(db backend.DB) *Store {
	return &Store{
		db: db,
	}
}

// AdmitSegmentReservation receives a setup/renewal request to admit a segment reservation.
func (s *Store) AdmitSegmentReservation(ctx context.Context, req segment.SetupReq) error {
	return nil
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
