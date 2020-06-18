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

package reservationdbtest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/cs/reservation/segmenttest"
	"github.com/scionproto/scion/go/cs/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/xtest"
)

type TestableDB interface {
	backend.DB
	Prepare(*testing.T, context.Context)
}

func TestDB(t *testing.T, db TestableDB) {
	tests := map[string]func(context.Context, *testing.T, backend.DB){
		"insert segment reservations create ID": testNewSegmentRsv,
		"insert segment reservation with ID":    testNewSegmentRsvWithID,
		"insert segment index":                  testNewSegmentIndex,
		"get segment reservation from ID":       testGetSegmentRsvFromID,
		"get segment reservations from src/dst": testGetSegmentRsvsFromSrcDstIA,
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			db.Prepare(t, ctx)
			test(ctx, t, db)
		})
	}
}

func testNewSegmentRsv(ctx context.Context, t *testing.T, db backend.DB) {
	r := newTestReservation(t)
	r.Indices = segment.Indices{}
	// no indices
	err := db.NewSegmentRsv(ctx, r)
	require.Error(t, err)
	// at least one index
	token := newToken()
	expTime := time.Unix(1, 0)
	r.NewIndex(expTime, *token)
	err = db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	require.Equal(t, xtest.MustParseHexString("00000001"), r.ID.Suffix[:])
	require.Len(t, r.Indices, 1)
	require.Equal(t, *token, r.Indices[0].Token)
}

func testNewSegmentRsvWithID(ctx context.Context, t *testing.T, db backend.DB) {
	r := newTestReservation(t)
	copy(r.ID.Suffix[:], xtest.MustParseHexString("beefcafe"))
	r.Indices = segment.Indices{}
	// no indices
	err := db.NewSegmentRsvWithID(ctx, r)
	require.Error(t, err)
	// at least one index
	token := newToken()
	expTime := time.Unix(1, 0)
	r.NewIndex(expTime, *token)
	err = db.NewSegmentRsvWithID(ctx, r)
	require.NoError(t, err)

	r2, err := db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, r2)
}

func testNewSegmentIndex(ctx context.Context, t *testing.T, db backend.DB) {
	r := newTestReservation(t)
	r.Indices = segment.Indices{}
	// no index
	err := db.NewSegmentRsv(ctx, r)
	require.Error(t, err)
	// one index (add 3, remove 2 to change its IndexNumber)
	expTime := time.Unix(1, 0)
	_, err = r.NewIndex(expTime, *newToken())
	require.NoError(t, err)
	_, err = r.NewIndex(expTime, *newToken())
	require.NoError(t, err)
	_, err = r.NewIndex(expTime, *newToken())
	require.NoError(t, err)
	err = r.RemoveIndex(1)
	require.NoError(t, err)
	require.Len(t, r.Indices, 1)
	r.SetIndexConfirmed(reservation.IndexNumber(2))
	err = r.SetIndexConfirmed(2)
	require.NoError(t, err)
	r.Indices[0].MinBW = 3
	r.Indices[0].MaxBW = 4
	r.Indices[0].AllocBW = 5
	r.Indices[0].Token.BWCls = 2
	err = db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	// read the reservation
	r2, err := db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, r2)
}

func testGetSegmentRsvFromID(ctx context.Context, t *testing.T, db backend.DB) {
	r := newTestReservation(t)
	err := db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	// create new index
	expTime := time.Unix(1, 0)
	idx, err := r.NewIndex(expTime, *newToken())
	require.NoError(t, err)
	r.Indices[1].Token.BWCls = 3
	err = db.NewSegmentIndex(ctx, r, idx)
	require.NoError(t, err)
	r2, err := db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, r2)
	// 14 more indices for a total of 16
	require.Len(t, r.Indices, 2)
	for i := 2; i < 16; i++ {
		expTime = time.Unix(int64(i), 0)
		idx, err = r.NewIndex(expTime, *newToken())
		require.NoError(t, err)
		r.Indices[i].MinBW = reservation.BWCls(i)
		r.Indices[i].MaxBW = reservation.BWCls(i)
		r.Indices[i].AllocBW = reservation.BWCls(i)
		r.Indices[i].Token.BWCls = reservation.BWCls(i)
		err = db.NewSegmentIndex(ctx, r, idx)
		require.NoError(t, err)
	}
	require.Len(t, r.Indices, 16)
	r2, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, r2)
}

func testGetSegmentRsvsFromSrcDstIA(ctx context.Context, t *testing.T, db backend.DB) {
	r := newTestReservation(t)
	err := db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	rsvs, err := db.GetSegmentRsvsFromSrcDstIA(ctx, r.Path.GetSrcIA(), r.Path.GetDstIA())
	require.NoError(t, err)
	require.Len(t, rsvs, 1)
	require.Equal(t, r, rsvs[0])
	// another reservation with same source and destination
	r2 := newTestReservation(t)
	err = db.NewSegmentRsv(ctx, r2)
	require.NoError(t, err)
	rsvs, err = db.GetSegmentRsvsFromSrcDstIA(ctx, r.Path.GetSrcIA(), r.Path.GetDstIA())
	require.NoError(t, err)
	require.Len(t, rsvs, 2)
	// compare without order
	require.ElementsMatch(t, rsvs, []*segment.Reservation{r, r2})
	// one more with same source different destination
	r3 := newTestReservation(t)
	r3.Path = segmenttest.NewPathFromComponents(0, "1-ff00:0:1", 1, 1, "1-ff00:0:3", 0)
	err = db.NewSegmentRsv(ctx, r3)
	require.NoError(t, err)
	rsvs, err = db.GetSegmentRsvsFromSrcDstIA(ctx, r.Path.GetSrcIA(), r.Path.GetDstIA())
	require.NoError(t, err)
	require.Len(t, rsvs, 2)
	require.ElementsMatch(t, rsvs, []*segment.Reservation{r, r2})
	rsvs, err = db.GetSegmentRsvsFromSrcDstIA(ctx, r.Path.GetSrcIA(), addr.IA{})
	require.NoError(t, err)
	require.Len(t, rsvs, 3)
	require.ElementsMatch(t, rsvs, []*segment.Reservation{r, r2, r3})
	// another reservation with unique source but same destination as r3
	r4 := newTestReservation(t)
	r4.Path = segmenttest.NewPathFromComponents(0, "1-ff00:0:4", 1, 1, "1-ff00:0:3", 0)
	err = db.NewSegmentRsv(ctx, r4)
	require.NoError(t, err)
	rsvs, err = db.GetSegmentRsvsFromSrcDstIA(ctx, r.Path.GetSrcIA(), r.Path.GetDstIA())
	require.NoError(t, err)
	require.Len(t, rsvs, 2)
	require.ElementsMatch(t, rsvs, []*segment.Reservation{r, r2})
	rsvs, err = db.GetSegmentRsvsFromSrcDstIA(ctx, r.Path.GetSrcIA(), addr.IA{})
	require.NoError(t, err)
	require.Len(t, rsvs, 3)
	require.ElementsMatch(t, rsvs, []*segment.Reservation{r, r2, r3})
	rsvs, err = db.GetSegmentRsvsFromSrcDstIA(ctx, addr.IA{}, r.Path.GetDstIA())
	require.NoError(t, err)
	require.Len(t, rsvs, 2)
	require.ElementsMatch(t, rsvs, []*segment.Reservation{r, r2})
	rsvs, err = db.GetSegmentRsvsFromSrcDstIA(ctx, addr.IA{}, r3.Path.GetDstIA())
	require.NoError(t, err)
	require.Len(t, rsvs, 2)
	require.ElementsMatch(t, rsvs, []*segment.Reservation{r3, r4})
}

// newToken just returns a token that can be serialized. This one has two HopFields.
func newToken() *reservation.Token {
	t, err := reservation.TokenFromRaw(xtest.MustParseHexString(
		"16ebdb4f0d042500003f001002bad1ce003f001002facade"))
	if err != nil {
		panic("invalid serialized token")
	}
	return t
}

func newTestReservation(t *testing.T) *segment.Reservation {
	t.Helper()
	r := segment.NewReservation()
	r.Path = segmenttest.NewPathFromComponents(0, "1-ff00:0:1", 1, 1, "1-ff00:0:2", 0)
	r.ID.ASID = xtest.MustParseAS("ff00:0:1")
	r.Ingress = 0
	r.Egress = 1
	r.TrafficSplit = 3
	r.PathEndProps = reservation.EndLocal | reservation.StartLocal
	expTime := time.Unix(1, 0)
	_, err := r.NewIndex(expTime, *newToken())
	require.NoError(t, err)
	r.Indices[0].Token.BWCls = 2
	err = r.SetIndexConfirmed(0)
	require.NoError(t, err)
	return r
}
