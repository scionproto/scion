// Copyright 2026 ETH Zurich
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

package hummingbird

import (
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
)

// Reservation represents a possibly partially reserved path, with zero or more flyovers.
type Reservation struct {
	dec   *hummingbird.Decoded // caches a decoded path for multiple uses
	hops  []Hop                // possible flyovers, one per dec.HopField that has a flyover.
	now   time.Time            // the current time
	minBW uint16               // the minimum required bandwidth

	counter uint32 // duplicate detection counter
}

// NewReservation creates a new reservation object. The option setting functions are executed in
// the order they appear in the slice.
func NewReservation(opts ...reservationModFcn) (*Reservation, error) {
	r := &Reservation{
		now: time.Now(),
	}
	// Run all options on this object.
	for _, fcn := range opts {
		if err := fcn(r); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// reservationModFcn is a options setting function for a reservation.
type reservationModFcn func(*Reservation) error

// WithNow modifies the current point in time for this reservation. It is useful to filter
// the different flyovers that can be passed to WithScionPath.
func WithNow(now time.Time) reservationModFcn {
	return func(r *Reservation) error {
		r.now = now
		return nil
	}
}

// WithMinBW modifies the minimum bandwidth required when filtering flyovers at the time of
// reservation creation.
func WithMinBW(bw uint16) reservationModFcn {
	return func(r *Reservation) error {
		r.minBW = bw
		return nil
	}
}

// FlyoverPerHopField returns a slice of pointers to flyovers, one per hop field present in the path,
// i.e. the length of the slice is the hop field count.
// If a hop field is not covered by a flyover, nil is used in its place.
func (r *Reservation) FlyoverPerHopField() []*Flyover {
	flyovers := make([]*Flyover, len(r.dec.HopFields))
	for hopIdx, i := 0, 0; i < len(flyovers) && hopIdx < len(r.hops); i++ {
		var flyover *Flyover
		if r.hops[hopIdx].Hopfield == &r.dec.HopFields[i] {
			flyover = r.hops[hopIdx].Flyover
			hopIdx++
		}
		flyovers[i] = flyover
	}

	return flyovers
}

func (r *Reservation) FlyoverAndHFCount() (int, int) {
	return len(r.hops), len(r.dec.HopFields)
}

func (r *Reservation) Destination() addr.IA {
	return r.hops[len(r.hops)-1].Flyover.IA
}

func (r *Reservation) GetHummingbirdPath() *hummingbird.Decoded {
	return r.dec
}

type Hop struct {
	Hopfield *hummingbird.FlyoverHopField // dataplane hop field
	Flyover  *Flyover                     // flyover used to build this hop
}

// Describes a pair of Ingress and Egress interfaces in a specific AS
type BaseHop struct {
	// IA denotes the IA for which a reservation is valid
	IA addr.IA
	// Ingress is the ingress interface for the reserved hop
	Ingress uint16
	// Egress is the egress interface of the reserved hop
	Egress uint16
}

type Flyover struct {
	BaseHop

	// ResID is the reservation ID of the reservation. It is unique PER AS
	ResID uint32
	// Ak is the authentication key of the reservation
	Ak [16]byte
	// Bw is the reserved Bandwidth
	Bw uint16
	// StartTime is the unix timestamp for the start of the reservation
	StartTime uint32
	// Duration is the duration of the reservation in seconds
	Duration uint16
}
