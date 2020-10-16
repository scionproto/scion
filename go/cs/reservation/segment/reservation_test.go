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

package segment_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/cs/reservation/segmenttest"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/util"
)

func TestNewIndexAtSource(t *testing.T) {
	r := segmenttest.NewReservation()
	require.Len(t, r.Indices, 0)
	expTime := util.SecsToTime(1)
	idx, err := r.NewIndexAtSource(expTime, 1, 3, 2, 5, reservation.CorePath)
	require.NoError(t, err)
	require.Len(t, r.Indices, 1)
	require.Equal(t, reservation.IndexNumber(0), idx)
	require.Equal(t, idx, r.Indices[0].Idx)
	require.Equal(t, expTime, r.Indices[0].Expiration)
	require.Equal(t, segment.IndexTemporary, r.Indices[0].State())
	require.Equal(t, reservation.BWCls(1), r.Indices[0].MinBW)
	require.Equal(t, reservation.BWCls(3), r.Indices[0].MaxBW)
	require.Equal(t, reservation.BWCls(2), r.Indices[0].AllocBW)
	require.NotNil(t, r.Indices[0].Token)
	tok := &reservation.Token{
		InfoField: reservation.InfoField{
			ExpirationTick: reservation.TickFromTime(expTime),
			BWCls:          2,
			RLC:            5,
			Idx:            idx,
			PathType:       reservation.CorePath,
		},
	}
	require.Equal(t, tok, r.Indices[0].Token)
	// add a second index
	idx, err = r.NewIndexAtSource(expTime, 1, 3, 2, 5, reservation.CorePath)
	require.NoError(t, err)
	require.Len(t, r.Indices, 2)
	require.Equal(t, reservation.IndexNumber(1), idx)
	require.Equal(t, idx, r.Indices[1].Idx)
	// remove first index and add another one
	r.Indices = r.Indices[1:]
	idx, err = r.NewIndexAtSource(expTime, 1, 3, 2, 5, reservation.CorePath)
	require.NoError(t, err)
	require.Len(t, r.Indices, 2)
	require.Equal(t, reservation.IndexNumber(2), idx)
	require.Equal(t, idx, r.Indices[1].Idx)
}

func TestNewIndexFromToken(t *testing.T) {
	r := segmenttest.NewReservation()
	require.Len(t, r.Indices, 0)
	expTime := time.Unix(1, 0)
	tok := &reservation.Token{
		InfoField: reservation.InfoField{
			ExpirationTick: reservation.TickFromTime(expTime),
			BWCls:          2,
			RLC:            5,
			Idx:            reservation.IndexNumber(6),
			PathType:       reservation.CorePath,
		},
	}
	idx, err := r.NewIndexFromToken(tok, 1, 3)
	require.NoError(t, err)
	require.Equal(t, tok.Idx, idx)
	require.Equal(t, tok.ExpirationTick.ToTime(), r.Indices[0].Expiration)
	require.Equal(t, segment.IndexTemporary, r.Indices[0].State())
	require.Equal(t, reservation.BWCls(1), r.Indices[0].MinBW)
	require.Equal(t, reservation.BWCls(3), r.Indices[0].MaxBW)
	require.Equal(t, tok.BWCls, r.Indices[0].AllocBW)
	require.Nil(t, r.Indices[0].Token)
	// nil token
	_, err = r.NewIndexFromToken(nil, 0, 0)
	require.Error(t, err)
}

func TestReservationValidate(t *testing.T) {
	r := segmenttest.NewReservation()
	err := r.Validate()
	require.NoError(t, err)
	// wrong path
	r.Path = segment.ReservationTransparentPath{}
	err = r.Validate()
	require.Error(t, err)
	// more than one active index
	expTime := util.SecsToTime(1)
	r = segmenttest.NewReservation()
	r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	require.Len(t, r.Indices, 2)
	r.Indices[0].SetStateForTesting(segment.IndexActive)
	r.Indices[1].SetStateForTesting(segment.IndexActive)
	err = r.Validate()
	require.Error(t, err)
	// ID not set
	r = segmenttest.NewReservation()
	r.ID = reservation.SegmentID{}
	err = r.Validate()
	require.Error(t, err)
	// starts in this AS but ingress nonzero
	r = segmenttest.NewReservation()
	r.Ingress = 1
	err = r.Validate()
	require.Error(t, err)
	// Does not start in this AS but ingress empty
	r = segmenttest.NewReservation()
	r.Path = nil
	err = r.Validate()
	require.Error(t, err)
}

func TestIndex(t *testing.T) {
	r := segmenttest.NewReservation()
	expTime := util.SecsToTime(1)
	r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	idx, _ := r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	require.Len(t, r.Indices, 3)
	index := r.Index(idx)
	require.Equal(t, &r.Indices[1], index)
	index = r.Index(reservation.IndexNumber(4))
	require.Nil(t, index)
	r.SetIndexConfirmed(idx)
	r.SetIndexActive(idx)
	index = r.Index(idx)
	require.Equal(t, &r.Indices[0], index)
}

func TestSetIndexConfirmed(t *testing.T) {
	r := segmenttest.NewReservation()
	expTime := util.SecsToTime(1)
	id, _ := r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	require.Equal(t, segment.IndexTemporary, r.Indices[0].State())
	err := r.SetIndexConfirmed(id)
	require.NoError(t, err)
	require.Equal(t, segment.IndexPending, r.Indices[0].State())

	// confirm already confirmed
	err = r.SetIndexConfirmed(id)
	require.NoError(t, err)
	require.Equal(t, segment.IndexPending, r.Indices[0].State())
}

func TestSetIndexActive(t *testing.T) {
	r := segmenttest.NewReservation()
	expTime := util.SecsToTime(1)

	// index not confirmed
	idx, _ := r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	err := r.SetIndexActive(idx)
	require.Error(t, err)

	// normal activation
	r.SetIndexConfirmed(idx)
	err = r.SetIndexActive(idx)
	require.NoError(t, err)
	require.Equal(t, segment.IndexActive, r.Indices[0].State())
	require.Equal(t, 0, r.GetActiveIndexForTesting())

	// already active
	err = r.SetIndexActive(idx)
	require.NoError(t, err)

	// remove previous indices
	r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	idx, _ = r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	require.Len(t, r.Indices, 3)
	require.Equal(t, 0, r.GetActiveIndexForTesting())
	r.SetIndexConfirmed(idx)
	err = r.SetIndexActive(idx)
	require.NoError(t, err)
	require.Len(t, r.Indices, 1)
	require.Equal(t, 0, r.GetActiveIndexForTesting())
	require.True(t, r.Indices[0].Idx == idx)
}

func TestRemoveIndex(t *testing.T) {
	r := segmenttest.NewReservation()
	expTime := util.SecsToTime(1)
	idx, _ := r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	err := r.RemoveIndex(idx)
	require.NoError(t, err)
	require.Len(t, r.Indices, 0)

	// remove second index
	idx, _ = r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	idx2, _ := r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	err = r.RemoveIndex(idx)
	require.NoError(t, err)
	require.Len(t, r.Indices, 1)
	require.True(t, r.Indices[0].Idx == idx2)
	err = r.Validate()
	require.NoError(t, err)

	// remove also removes older indices
	expTime = expTime.Add(time.Second)
	r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	idx, _ = r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	idx2, _ = r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	require.Len(t, r.Indices, 4)
	err = r.RemoveIndex(idx)
	require.NoError(t, err)
	require.Len(t, r.Indices, 1)
	require.True(t, r.Indices[0].Idx == idx2)
	err = r.Validate()
	require.NoError(t, err)
}

func TestMaxBlockedBW(t *testing.T) {
	r := segmenttest.NewReservation()
	r.Indices = r.Indices[:0]
	require.Equal(t, uint64(0), r.MaxBlockedBW())
	r.NewIndexAtSource(util.SecsToTime(1), 1, 1, 1, 1, reservation.CorePath)
	require.Equal(t, reservation.BWCls(1).ToKbps(), r.MaxBlockedBW())
	r.NewIndexAtSource(util.SecsToTime(1), 1, 1, 1, 1, reservation.CorePath)
	require.Equal(t, reservation.BWCls(1).ToKbps(), r.MaxBlockedBW())
	r.Indices[0].AllocBW = 11
	require.Equal(t, reservation.BWCls(11).ToKbps(), r.MaxBlockedBW())
}
