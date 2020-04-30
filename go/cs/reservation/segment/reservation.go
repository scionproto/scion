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

package segment

import (
	"time"

	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Reservation represents a segment reservation.
type Reservation struct {
	ID          reservation.SegmentID
	Path        Path
	Indices     []Index
	activeIndex int // -1 <= activeIndex < len(Indices)
}

// Validate will return an error for invalid values.
func (r *Reservation) Validate() error {
	if r.activeIndex < -1 || r.activeIndex > 0 || r.activeIndex >= len(r.Indices) {
		// when we activate an index all previous indices are removed.
		// Thus activeIndex can only be -1 or 0
		return serrors.New("invalid active index", "active_index", r.activeIndex)
	}
	if len(r.Indices) > 16 {
		// with only 4 bits to represent the index number, we cannot have more than 16 indices
		return serrors.New("invalid number of indices", "index_count", len(r.Indices))
	}
	// check indices: ascending order and only three per expiration time
	if len(r.Indices) > 0 {
		lastExpiration := time.Unix(0, 0)
		var lastIndexNumber reservation.IndexNumber = reservation.IndexNumber(0).Sub(1)
		indicesPerExpTime := 0
		activeIndex := -1
		for i, idx := range r.Indices {
			if idx.Expiration.Before(lastExpiration) {
				return serrors.New("invalid Index: expires before than a previous one",
					"idx", idx.Idx, "expiration", idx.Expiration, "previous_exp", lastExpiration)
			}
			if idx.Expiration.Equal(lastExpiration) {
				indicesPerExpTime++
				if indicesPerExpTime > 3 {
					return serrors.New("more than one index for expiration time",
						"expiration", idx.Expiration)
				}
			} else {
				indicesPerExpTime = 1
			}
			if idx.Idx.Sub(lastIndexNumber) != reservation.IndexNumber(1) {
				return serrors.New("non consecutive indices", "prev_index_number", lastIndexNumber,
					"index_number", idx.Idx)
			}
			if idx.state == IndexActive {
				if activeIndex >= 0 {
					return serrors.New("more than one active index",
						"first_active", r.Indices[activeIndex].Idx, "another_active", idx.Idx)
				}
				activeIndex = i
			}
			lastExpiration = idx.Expiration
			lastIndexNumber = idx.Idx
		}
	}
	return r.Path.Validate()
}

// ActiveIndex returns the currently active Index for this reservation, or nil if none.
func (r *Reservation) ActiveIndex() *Index {
	if r.activeIndex == -1 {
		return nil
	}
	return &r.Indices[r.activeIndex]
}

// NewIndex creates a new index in this reservation and returns a pointer to it.
// Parameters of this index can be changed using the pointer, except for the state.
func (r *Reservation) NewIndex(expTime time.Time) (reservation.IndexNumber, error) {
	lastExpTime := time.Unix(0, 0)
	var indexNumber reservation.IndexNumber = 0
	if len(r.Indices) > 0 {
		lastExpTime = r.Indices[len(r.Indices)-1].Expiration
		indexNumber = r.Indices[len(r.Indices)-1].Idx.Add(1)
	}
	if expTime.Before(lastExpTime) {
		return 0, serrors.New("new index attempt on a too old expiration time",
			"exp time", expTime, "last recorded exp time", lastExpTime)
	}
	numberOfIndicesPerExpTime := 1
	for i := len(r.Indices) - 1; i >= 0 && numberOfIndicesPerExpTime <= 3; i-- {
		if !expTime.Equal(r.Indices[i].Expiration) {
			break
		}
		numberOfIndicesPerExpTime++
	}
	if numberOfIndicesPerExpTime > 3 {
		return 0, serrors.New("only 3 indices allowed per expiration time",
			"exp. time", expTime)
	}

	index := Index{
		Expiration: expTime,
		Idx:        reservation.IndexNumber(indexNumber).Add(0),
		state:      IndexTemporary,
	}
	r.Indices = append(r.Indices, index)
	return index.Idx, nil
}

// SetIndexConfirmed sets the index as IndexPending (confirmed but not active). If the requested
// index has state active, it will emit an error.
func (r *Reservation) SetIndexConfirmed(idx reservation.IndexNumber) error {
	sliceIndex := r.findIndex(idx)
	if sliceIndex < 0 {
		return serrors.New("index does not belong to this reservation", "index_number", idx,
			"indices length", len(r.Indices))
	}
	if r.Indices[sliceIndex].state == IndexActive {
		return serrors.New("cannot confirm an already active index", "index_number", idx)
	}
	r.Indices[sliceIndex].state = IndexPending
	return nil
}

// SetIndexActive sets the index as active. If the reservation had already an active state,
// it will remove all previous indices.
func (r *Reservation) SetIndexActive(idx reservation.IndexNumber) error {
	sliceIndex := r.findIndex(idx)
	if sliceIndex < 0 {
		return serrors.New("index does not belong to this reservation", "index_number", idx,
			"indices length", len(r.Indices))
	}
	if r.activeIndex == sliceIndex {
		return nil // already active
	}
	if r.Indices[sliceIndex].state != IndexPending {
		return serrors.New("attempt to activate a non confirmed index", "index_number", idx,
			"state", r.Indices[sliceIndex].state)
	}
	if r.activeIndex > -1 {
		if r.activeIndex > sliceIndex {
			return serrors.New("activating a past index",
				"last active", r.Indices[r.activeIndex].Idx, "current", idx)
		}
	}
	// remove indices [lastActive,currActive) so that currActive is at position 0
	r.Indices = r.Indices[sliceIndex:]
	r.activeIndex = 0
	r.Indices[0].state = IndexActive
	return nil
}

// RemoveIndex removes all indices from the beginning until this one, inclusive.
func (r *Reservation) RemoveIndex(idx reservation.IndexNumber) error {
	sliceIndex := r.findIndex(idx)
	if sliceIndex < 0 {
		return serrors.New("index does not belong to this reservation", "index_number", idx,
			"indices length", len(r.Indices))
	}
	r.Indices = r.Indices[sliceIndex+1:]
	r.activeIndex -= sliceIndex
	if r.activeIndex < -1 {
		r.activeIndex = -1
	}
	return nil
}

func (r *Reservation) findIndex(idx reservation.IndexNumber) int {
	var firstIdx reservation.IndexNumber = 0
	if len(r.Indices) > 0 {
		firstIdx = r.Indices[0].Idx
	}
	sliceIndex := int(idx.Sub(firstIdx))
	if sliceIndex > len(r.Indices)-1 {
		return -1
	}
	return sliceIndex
}
