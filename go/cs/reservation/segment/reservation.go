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
		return serrors.New("Invalid active index", "activeIndex", r.activeIndex)
	}
	// check indices: ascending order and only three per expiration time
	if len(r.Indices) > 0 {
		lastIndex := r.Indices[0].Idx - 1
		lastExpiration := time.Unix(0, 0)
		indicesPerExpTime := 0
		var activeIndex *Index
		for _, idx := range r.Indices {
			if idx.Idx != lastIndex+1 {
				return serrors.New(("Non consecutive index"))
			}
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
			} else {
				indicesPerExpTime = 1
			}
			if idx.state == IndexActive {
				if activeIndex != nil {
					return serrors.New("More than one active index",
						"first active", activeIndex.Idx, "another active", idx.Idx)
				}
				activeIndex = &idx
			}
		}
	}
	return nil
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
func (r *Reservation) NewIndex() *Index {
	lastIdx := 0
	if len(r.Indices) > 0 {
		lastIdx = int(r.Indices[len(r.Indices)-1].Idx)
	}
	index := Index{
		Idx:   reservation.Index(lastIdx + 1),
		state: IndexTemporary,
	}
	r.Indices = append(r.Indices, index)
	return &index
}

func (r *Reservation) SetIndexState(index *Index, state IndexState) error {
	// consecutive indices in the array:
	firstIdx := 1 << 30
	if len(r.Indices) > 0 {
		firstIdx = int(r.Indices[0].Idx)
	}
	idx := int(index.Idx) - firstIdx
	if idx < 0 || idx > len(r.Indices) {
		return serrors.New("Wrong index in reservation Index", "index", index.Idx,
			"lowest", firstIdx, "Indices length", len(r.Indices))
	}
	return nil
}
