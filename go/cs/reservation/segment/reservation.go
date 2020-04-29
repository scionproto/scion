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
	if r.activeIndex < -1 || r.activeIndex >= len(r.Indices) {
		// TODO(juagargi) according to Reservation.SetState, when we activate an index,
		// all previous indices are removed. Thus activeIndex can only be -1 or 0 ?
		return serrors.New("Invalid active index", "activeIndex", r.activeIndex)
	}
	// check indices: ascending order and only three per expiration time
	if len(r.Indices) > 0 {
		lastExpiration := time.Unix(0, 0)
		indicesPerExpTime := 0
		activeIndex := -1
		for i, idx := range r.Indices {
			if idx.Expiration.Before(lastExpiration) {
				return serrors.New("Invalid Index: expires before than a previous one",
					"idx", idx.Idx, "expiration", idx.Expiration, "previous exp.", lastExpiration)
			}
			if idx.Expiration.Equal(lastExpiration) {
				indicesPerExpTime++
				if indicesPerExpTime > 3 {
					return serrors.New("More than one index for expiration time",
						"expiration", idx.Expiration)
				}
				if int(idx.Idx) != indicesPerExpTime-1 {
					return serrors.New("non consecutive indices", "index", idx.Idx,
						"exp. time", lastExpiration)
				}
			} else {
				indicesPerExpTime = 1
			}
			if idx.state == IndexActive {
				if activeIndex >= 0 {
					return serrors.New("More than one active index",
						"first active", r.Indices[activeIndex].Idx, "another active", idx.Idx)
				}
				activeIndex = i
			}
			lastExpiration = idx.Expiration
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
func (r *Reservation) NewIndex(expTime time.Time) (*IndexID, error) {
	lastExpTime := time.Unix(0, 0)
	if len(r.Indices) > 0 {
		lastExpTime = r.Indices[len(r.Indices)-1].Expiration
	}
	if expTime.Before(lastExpTime) {
		return nil, serrors.New("new index attempt on a too old expiration time",
			"exp time", expTime, "last recorded exp time", lastExpTime)
	}
	indexNumber := 0
	if expTime.Equal(lastExpTime) {
		// no more than 3 per exp time
		indexNumber++
		for i := len(r.Indices) - 2; i >= 0 && indexNumber < 3; i-- {
			if r.Indices[i].Expiration.Equal(lastExpTime) {
				indexNumber++
			} else {
				break
			}
		}
		if indexNumber > 2 {
			return nil, serrors.New("only 3 indices allowed per expiration time",
				"exp. time", expTime)
		}
		if r.Indices[len(r.Indices)-1].Idx == 2 {
			// even though we currently don't have more than 3 indices, the index number of the
			// last one is "2" and forces this index number to be 3, which is too big to be
			// represented with 2 bits later on.
			return nil, serrors.New("index number too big", "number of indices", len(r.Indices))
		}
		// if from 0,1 we had removed 0, the nextIndex should be 2
		indexNumber = int(r.Indices[len(r.Indices)-1].Idx) + 1
	}
	index := Index{
		IndexID: IndexID{Expiration: expTime, Idx: reservation.Index(indexNumber)},
		state:   IndexTemporary,
	}
	r.Indices = append(r.Indices, index)
	return &index.IndexID, nil
}

// SetIndexConfirmed sets the index as IndexPending (confirmed but not active). If the requested
// index has state active, it will emit an error.
func (r *Reservation) SetIndexConfirmed(id *IndexID) error {
	sliceIndex := r.findIndex(id)
	if sliceIndex < 0 {
		return serrors.New("index does not belong to this reservation", "id", id,
			"indices length", len(r.Indices))
	}
	if r.Indices[sliceIndex].state == IndexActive {
		return serrors.New("cannot confirm an already active index", "id", id)
	}
	r.Indices[sliceIndex].state = IndexPending
	return nil
}

// SetIndexActive sets the index as active. If the reservation had already an active state,
// it will remove all previous indices.
func (r *Reservation) SetIndexActive(id *IndexID) error {
	sliceIndex := r.findIndex(id)
	if sliceIndex < 0 {
		return serrors.New("index does not belong to this reservation", "id", id,
			"indices length", len(r.Indices))
	}
	if r.activeIndex == sliceIndex {
		return nil // already active
	}
	if r.Indices[sliceIndex].state != IndexPending {
		return serrors.New("attempt to activate a non confirmed index", "id", id,
			"state", r.Indices[sliceIndex].state)
	}
	if r.activeIndex > -1 {

		if r.activeIndex > sliceIndex {
			return serrors.New("activating a past index",
				"last active", r.Indices[r.activeIndex].Idx, "current", id)
		}
	}
	// remove indices [lastActive,currActive) so that currActive is at position 0
	r.Indices = r.Indices[sliceIndex:]
	r.activeIndex = 0
	r.Indices[0].state = IndexActive
	return nil
}

// RemoveIndex removes all indices from the beginning until this one, inclusive.
func (r *Reservation) RemoveIndex(id *IndexID) error {
	sliceIndex := r.findIndex(id)
	if sliceIndex < 0 {
		return serrors.New("index does not belong to this reservation", "id", id,
			"indices length", len(r.Indices))
	}
	r.Indices = r.Indices[sliceIndex+1:]
	r.activeIndex -= sliceIndex
	if r.activeIndex < -1 {
		r.activeIndex = -1
	}
	return nil
}

func (r *Reservation) findIndex(id *IndexID) int {
	for i, idx := range r.Indices {
		if idx.IndexID.Equal(id) {
			return i
		}
	}
	return -1
}
