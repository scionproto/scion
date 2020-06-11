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

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Reservation represents a segment reservation.
type Reservation struct {
	ID           reservation.SegmentID
	Indices      Indices                  // existing indices in this reservation
	activeIndex  int                      // -1 <= activeIndex < len(Indices)
	IngressIFID  common.IFIDType          // igress interface ID: reservation packets enter
	EgressIFID   common.IFIDType          // egress interface ID: reservation packets leave
	Path         *Path                    // nil if this AS is not at the source of the reservation
	PathEndProps reservation.PathEndProps // the properties for stitching and start/end
	TrafficSplit reservation.SplitCls     // the traffic split between control and data planes
}

func NewReservation() *Reservation {
	return &Reservation{
		activeIndex: -1,
	}
}

// Validate will return an error for invalid values.
func (r *Reservation) Validate() error {
	if r.ID.ASID == 0 {
		return serrors.New("Reservation ID not set")
	}
	if err := base.ValidateIndices(r.Indices); err != nil {
		return err
	}
	if r.activeIndex < -1 || r.activeIndex > 0 || r.activeIndex >= len(r.Indices) {
		// when we activate an index all previous indices are removed.
		// Thus activeIndex can only be -1 or 0
		return serrors.New("invalid active index", "active_index", r.activeIndex)
	}
	activeIndex := -1
	for i, index := range r.Indices {
		if index.State() == IndexActive {
			if activeIndex != -1 {
				return serrors.New("more than one active index",
					"first_active", r.Indices[activeIndex].Idx, "another_active", index.Idx)
			}
			activeIndex = i
		}
	}
	var err error
	if r.Path != nil {
		if r.IngressIFID != 0 {
			return serrors.New("reservation starts in this AS but ingress interface is not zero",
				"ingress_if", r.IngressIFID)
			// TODO(juagargi) test
		}
		err = r.Path.Validate()
	} else if r.IngressIFID == 0 {
		return serrors.New("reservation does not start in this AS but ingress interface is zero")
	}
	if err != nil {
		return serrors.WrapStr("validating reservation, path failed", err)
	}
	err = r.PathEndProps.Validate()
	if err != nil {
		return serrors.WrapStr("validating reservation, end properties failed", err)
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
		state:      IndexTemporary,
	}
	if err := base.ValidateIndices(newIndices); err != nil {
		return 0, err
	}
	r.Indices = newIndices
	return r.Indices[len(r.Indices)-1].Idx, nil
}

// SetIndexConfirmed sets the index as IndexPending (confirmed but not active). If the requested
// index has state active, it will emit an error.
func (r *Reservation) SetIndexConfirmed(idx reservation.IndexNumber) error {
	sliceIndex, err := base.FindIndex(r.Indices, idx)
	if err != nil {
		return err
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
	sliceIndex, err := base.FindIndex(r.Indices, idx)
	if err != nil {
		return err
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
	sliceIndex, err := base.FindIndex(r.Indices, idx)
	if err != nil {
		return err
	}
	r.Indices = r.Indices[sliceIndex+1:]
	r.activeIndex -= sliceIndex
	if r.activeIndex < -1 {
		r.activeIndex = -1
	}
	return nil
}
