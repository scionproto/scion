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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/cs/reservation/segmenttest"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestValidate(t *testing.T) {
	// alright
	r := newReservation()
	err := r.Validate()
	require.NoError(t, err)

	// no segment reservations
	r = newReservation()
	r.SegmentReservations = make([]*segment.Reservation, 0)
	err = r.Validate()
	require.Error(t, err)

	// nil segment reservation
	r = newReservation()
	r.SegmentReservations[0] = nil
	err = r.Validate()
	require.Error(t, err)

	// invalid segment reservation
	r = newReservation()
	r.SegmentReservations[0].Path = segment.Path{}
	err = r.Validate()
	require.Error(t, err)

	// more than 3 segment reservations
	r = newReservation()
	r.SegmentReservations = []*segment.Reservation{
		newSegmentReservation("1-ff00:0:111", "1-ff00:0:110"),
		newSegmentReservation("1-ff00:0:111", "1-ff00:0:110"),
		newSegmentReservation("1-ff00:0:111", "1-ff00:0:110"),
		newSegmentReservation("1-ff00:0:111", "1-ff00:0:110"),
	}
	err = r.Validate()
	require.Error(t, err)
}

func TestNewIndex(t *testing.T) {
	r := newReservation()
	expTime := util.SecsToTime(1)
	index, err := r.NewIndex(expTime)
	require.NoError(t, err)
	require.Len(t, r.Indices, 1)
	require.Equal(t, r.Indices[0].Idx, index)
}

func TestRemoveIndex(t *testing.T) {
	r := newReservation()
	expTime := util.SecsToTime(1)
	idx, _ := r.NewIndex(expTime)
	err := r.RemoveIndex(idx)
	require.NoError(t, err)
	require.Len(t, r.Indices, 0)
}

func newSegmentReservation(asidPath ...string) *segment.Reservation {
	if len(asidPath) < 2 {
		panic("at least source and destination in the path")
	}
	r := segmenttest.NewReservation()
	// use the asid to create an ID and a path and use them in the reservation
	pathComponents := make([]interface{}, len(asidPath)*3)
	for i := range asidPath {
		pathComponents[i*3] = i * 2
		pathComponents[i*3+1] = asidPath[i]
		pathComponents[i*3+2] = i*2 + 1
	}
	pathComponents[len(pathComponents)-1] = 0
	r.Path = segmenttest.NewPathFromComponents(pathComponents...)
	return r
}

func newReservation() *Reservation {
	id, err := reservation.NewE2EID(xtest.MustParseAS("ff00:0:111"),
		xtest.MustParseHexString("beefcafebeefcafebeef"))
	if err != nil {
		panic(err)
	}
	rsv := Reservation{
		ID: *id,
		SegmentReservations: []*segment.Reservation{
			newSegmentReservation("1-ff00:0:111", "1-ff00:0:110"),
		},
	}
	return &rsv
}
