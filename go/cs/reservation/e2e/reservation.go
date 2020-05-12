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

package e2e

import (
	"time"

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Reservation represents an E2E reservation.
type Reservation struct {
	ID                  reservation.E2EID
	SegmentReservations []*segment.Reservation // stitched segment reservations
	Indices             Indices
}

// Validate will return an error for invalid values.
func (r *Reservation) Validate() error {
	if err := base.ValidateIndices(r.Indices); err != nil {
		return err
	}
	if len(r.SegmentReservations) < 1 || len(r.SegmentReservations) > 3 {
		return serrors.New("wrong number of segment reservations referenced in E2E reservation",
			"number", len(r.SegmentReservations))
	}
	// TODO(juagargi) check for valid stitching? path properties and correct end/start AS ID?
	for i, rsv := range r.SegmentReservations {
		if rsv == nil {
			return serrors.New("invalid segment reservation referenced by e2e, is nil",
				"slice_index", i)
		}
		if err := rsv.Validate(); err != nil {
			return serrors.New("invalid segment reservation referenced by e2e one",
				"slice_index", i, "segment_id", rsv.ID)
		}
	}
	return nil
}

// NewIndex creates a new index in this reservation.
func (r *Reservation) NewIndex(expTime time.Time) (reservation.IndexNumber, error) {
	idx := reservation.IndexNumber(0)
	if len(r.Indices) > 0 {
		idx = r.Indices[len(r.Indices)-1].Idx.Add(1)
	}
	newIndices := make(Indices, len(r.Indices)+1)
	copy(newIndices, r.Indices)
	newIndices[len(newIndices)-1] = Index{
		Expiration: expTime,
		Idx:        idx,
	}
	if err := base.ValidateIndices(newIndices); err != nil {
		return 0, err
	}
	r.Indices = newIndices
	return r.Indices[len(r.Indices)-1].Idx, nil
}

// RemoveIndex removes all indices from the beginning until this one, inclusive.
func (r *Reservation) RemoveIndex(idx reservation.IndexNumber) error {
	sliceIndex, err := base.FindIndex(r.Indices, idx)
	if err != nil {
		return err
	}
	r.Indices = r.Indices[sliceIndex+1:]
	return nil
}
