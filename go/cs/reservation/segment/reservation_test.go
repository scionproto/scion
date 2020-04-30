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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestNewIndex(t *testing.T) {
	r := newReservation()
	require.Len(t, r.Indices, 0)
	expTime := time.Unix(1, 0)
	idx, err := r.NewIndex(expTime)
	require.NoError(t, err)
	require.Len(t, r.Indices, 1)
	require.Equal(t, r.Indices[0].Idx, idx)
	require.Equal(t, r.Indices[0].Expiration, expTime)
	require.Equal(t, idx, reservation.IndexNumber(0))

	// up to 3 indices per expiration time
	idx, err = r.NewIndex(expTime)
	require.NoError(t, err)
	require.Equal(t, idx, reservation.IndexNumber(1))
	idx, err = r.NewIndex(expTime)
	require.NoError(t, err)
	require.Equal(t, idx, reservation.IndexNumber(2))
	r.Indices = r.Indices[:1]

	// exp time is less
	_, err = r.NewIndex(expTime.Add(-1 * time.Millisecond))
	require.Error(t, err)
	require.Len(t, r.Indices, 1)

	// exp time is same
	idx, err = r.NewIndex(expTime)
	require.NoError(t, err)
	require.Len(t, r.Indices, 2)
	require.Equal(t, r.Indices[1].Idx, idx)
	require.Equal(t, r.Indices[1].Expiration, expTime)
	require.Equal(t, idx, reservation.IndexNumber(1))

	idx, err = r.NewIndex(expTime)
	require.NoError(t, err)
	require.Len(t, r.Indices, 3)
	require.Equal(t, r.Indices[2].Idx, idx)
	require.Equal(t, r.Indices[2].Expiration, expTime)
	require.Equal(t, idx, reservation.IndexNumber(2))

	// too many indices for the same exp time
	idx, err = r.NewIndex(expTime)
	require.Error(t, err)
	require.Len(t, r.Indices, 3)

	// exp time is greater
	expTime = expTime.Add(time.Second)
	idx, err = r.NewIndex(expTime)
	require.NoError(t, err)
	require.Len(t, r.Indices, 4)
	require.Equal(t, r.Indices[3].Idx, idx)
	require.Equal(t, r.Indices[3].Expiration, expTime)
	require.Equal(t, idx, reservation.IndexNumber(3))

	// index number rollover
	r = newReservation()
	r.NewIndex(expTime)
	require.Len(t, r.Indices, 1)
	r.Indices[0].Idx = r.Indices[0].Idx.Sub(1)
	idx, err = r.NewIndex(expTime)
	require.NoError(t, err)
	require.Equal(t, r.Indices[1].Idx, idx)
	require.Equal(t, r.Indices[1].Expiration, expTime)
	require.Equal(t, idx, reservation.IndexNumber(0))
}
func TestReservationValidate(t *testing.T) {
	r := newReservation()
	err := r.Validate()
	require.NoError(t, err)

	// more than 16 indices
	for i := 0; i < 16; i++ {
		expTime := time.Unix(int64(i), 0)
		r.NewIndex(expTime)
	}
	err = r.Validate()
	require.NoError(t, err)
	r.Indices = append(r.Indices, r.Indices[15])
	r.Indices[16].Idx.Add(1) // rollover
	err = r.Validate()
	require.Error(t, err)

	// wrong path
	r.Path = Path{}
	err = r.Validate()
	require.Error(t, err)

	r = newReservation()
	r.activeIndex = 0
	err = r.Validate()
	require.Error(t, err)

	// exp time is before
	r = newReservation()
	expTime := time.Unix(1, 0)
	r.NewIndex(expTime)
	r.NewIndex(expTime)
	r.Indices[1].Expiration = expTime.Add(-1 * time.Second)
	err = r.Validate()
	require.Error(t, err)

	// non consecutive indices
	r.Indices = r.Indices[:1] // remove tainted index
	r.NewIndex(expTime)
	err = r.Validate()
	require.NoError(t, err)
	r.Indices[1].Idx = 2
	err = r.Validate()
	require.Error(t, err)

	// more than three indices per exp time
	r.Indices = r.Indices[:1]
	r.NewIndex(expTime)
	r.NewIndex(expTime)
	err = r.Validate()
	require.NoError(t, err)
	_, err = r.NewIndex(expTime.Add(time.Second))
	require.NoError(t, err)
	r.Indices[3].Expiration = expTime
	r.Indices[3].Idx = 3
	err = r.Validate()
	require.Error(t, err)

	// more than one active index
	r.Indices = r.Indices[:1]
	r.NewIndex(expTime)
	r.Indices[0].state = IndexActive
	r.Indices[1].state = IndexActive
	err = r.Validate()
	require.Error(t, err)
}

func TestSetIndexConfirmed(t *testing.T) {
	r := newReservation()
	expTime := time.Unix(1, 0)
	id, _ := r.NewIndex(expTime)
	require.Equal(t, r.Indices[0].state, IndexTemporary)
	err := r.SetIndexConfirmed(id)
	require.NoError(t, err)
	require.Equal(t, r.Indices[0].state, IndexPending)

	// confirm already confirmed
	err = r.SetIndexConfirmed(id)
	require.NoError(t, err)
	require.Equal(t, r.Indices[0].state, IndexPending)
}

func TestSetIndexActive(t *testing.T) {
	r := newReservation()
	expTime := time.Unix(1, 0)

	// index not confirmed
	idx, _ := r.NewIndex(expTime)
	err := r.SetIndexActive(idx)
	require.Error(t, err)

	// normal activation
	r.SetIndexConfirmed(idx)
	err = r.SetIndexActive(idx)
	require.NoError(t, err)
	require.Equal(t, r.Indices[0].state, IndexActive)
	require.Equal(t, r.activeIndex, 0)

	// already active
	err = r.SetIndexActive(idx)
	require.NoError(t, err)

	// remove previous indices
	r.NewIndex(expTime)
	idx, _ = r.NewIndex(expTime)
	require.Len(t, r.Indices, 3)
	require.Equal(t, r.activeIndex, 0)
	r.SetIndexConfirmed(idx)
	err = r.SetIndexActive(idx)
	require.NoError(t, err)
	require.Len(t, r.Indices, 1)
	require.Equal(t, r.activeIndex, 0)
	require.Equal(t, r.Indices[0].Idx, idx)
}

func TestRemoveIndex(t *testing.T) {
	r := newReservation()
	expTime := time.Unix(1, 0)
	idx, _ := r.NewIndex(expTime)
	err := r.RemoveIndex(idx)
	require.NoError(t, err)
	require.Len(t, r.Indices, 0)

	idx, _ = r.NewIndex(expTime)
	idx2, _ := r.NewIndex(expTime)
	err = r.RemoveIndex(idx)
	require.NoError(t, err)
	require.Len(t, r.Indices, 1)
	require.Equal(t, r.Indices[0].Idx, idx2)

	expTime = expTime.Add(time.Second)
	r.NewIndex(expTime)
	idx, _ = r.NewIndex(expTime)
	idx2, _ = r.NewIndex(expTime)
	require.Len(t, r.Indices, 4)
	err = r.RemoveIndex(idx)
	require.NoError(t, err)
	require.Len(t, r.Indices, 1)
	require.Equal(t, r.Indices[0].Idx, idx2)
}

func newReservation() *Reservation {
	segID, err := reservation.NewSegmentID(xtest.MustParseAS("ff00:0:1"),
		xtest.MustParseHexString("beefcafe"))
	if err != nil {
		panic(err)
	}
	p := newPathFromComponents(0, "ff00:0:1", 1, 1, "ff00:0:2", 0)
	r := Reservation{
		ID:          *segID,
		Path:        p,
		activeIndex: -1,
	}
	return &r
}
