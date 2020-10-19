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
	"github.com/scionproto/scion/go/lib/serrors"
)

// Reservation represents a segment reservation.
type Reservation struct {
	ID           reservation.SegmentID
	Indices      Indices                    // existing indices in this reservation
	activeIndex  int                        // -1 <= activeIndex < len(Indices)
	Ingress      uint16                     // igress interface ID: reservation packets enter
	Egress       uint16                     // egress interface ID: reservation packets leave
	Path         ReservationTransparentPath // empty if not at the source of the reservation
	PathType     reservation.PathType       // the type of path (up,core,down)
	PathEndProps reservation.PathEndProps   // the properties for stitching and start/end
	TrafficSplit reservation.SplitCls       // the traffic split between control and data planes
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
		if r.Ingress != 0 {
			return serrors.New("reservation starts in this AS but ingress interface is not zero",
				"ingress_if", r.Ingress)
		}
		err = r.Path.Validate()
	} else if r.Ingress == 0 {
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

// NewIndexAtSource creates a new index. The associated token is created from the arguments, and
// automatically linked to the index. This function should be called only from the
// AS originating the reservation.
// The expiration times must always be greater or equal than those in previous indices.
func (r *Reservation) NewIndexAtSource(expTime time.Time, minBW, maxBW, allocBW reservation.BWCls,
	rlc reservation.RLC, pathType reservation.PathType) (reservation.IndexNumber, error) {

	idx := reservation.IndexNumber(0)
	if len(r.Indices) > 0 {
		idx = r.Indices[len(r.Indices)-1].Idx.Add(1)
	}
	tok := &reservation.Token{
		InfoField: reservation.InfoField{
			Idx:            idx,
			ExpirationTick: reservation.TickFromTime(expTime),
			BWCls:          allocBW,
			RLC:            rlc,
			PathType:       pathType,
		},
	}
	index := NewIndex(idx, expTime, IndexTemporary, minBW, maxBW, allocBW, tok)
	return r.addIndex(index)
}

// NewIndexFromToken creates a new index. The token argument is used to populate several
// fields of the index. The token is not stored (on-path ASes don't need the token).
// This function should be called from an AS that is on the reservation path
// but not the originating one.
func (r *Reservation) NewIndexFromToken(tok *reservation.Token, minBW, maxBW reservation.BWCls) (
	reservation.IndexNumber, error) {

	if tok == nil {
		return 0, serrors.New("token is nil")
	}
	index := NewIndex(tok.Idx, tok.ExpirationTick.ToTime(), IndexTemporary, minBW, maxBW,
		tok.BWCls, nil)
	return r.addIndex(index)
}

func (r *Reservation) addIndex(index *Index) (reservation.IndexNumber, error) {
	newIndices := make(Indices, len(r.Indices)+1)
	copy(newIndices, r.Indices)
	newIndices[len(newIndices)-1] = *index
	if err := base.ValidateIndices(newIndices); err != nil {
		return 0, err
	}
	r.Indices = newIndices
	return index.Idx, nil
}

// Index finds the Index with that IndexNumber and returns a pointer to it.
func (r *Reservation) Index(idx reservation.IndexNumber) *Index {
	sliceIndex, err := base.FindIndex(r.Indices, idx)
	if err != nil {
		return nil
	}
	return &r.Indices[sliceIndex]
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
	// valid states are Pending (nominal) and Active (reconstructing from DB needs this)
	if r.Indices[sliceIndex].state != IndexPending && r.Indices[sliceIndex].state != IndexActive {
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

// MaxBlockedBW returns the maximum bandwidth blocked by this reservation, which is
// the same as the maximum allocated bandwidth indicated by its indices.
func (r *Reservation) MaxBlockedBW() uint64 {
	if len(r.Indices) == 0 {
		return 0
	}
	var max reservation.BWCls
	for _, idx := range r.Indices {
		max = reservation.MaxBWCls(max, idx.AllocBW)
	}
	return max.ToKbps()
}

// MaxRequestedBW returns the maximum bandwidth requested by this reservation.
func (r *Reservation) MaxRequestedBW() uint64 {
	if len(r.Indices) == 0 {
		return 0
	}
	var max reservation.BWCls
	for _, idx := range r.Indices {
		max = reservation.MaxBWCls(max, idx.MaxBW)
	}
	return max.ToKbps()
}
