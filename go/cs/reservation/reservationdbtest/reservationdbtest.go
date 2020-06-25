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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/xtest"
)

type TestableDB interface {
	backend.DB
	Prepare(*testing.T, context.Context)
}

func TestDB(t *testing.T, db TestableDB) {
	tests := map[string]func(context.Context, *testing.T, backend.DB){
		"insert segment reservations create ID": testNewSegmentRsv,
		"persist segment reservation":           testPersistSegmentRsv,
		"get segment reservation from ID":       testGetSegmentRsvFromID,
		"get segment reservations from src/dst": testGetSegmentRsvsFromSrcDstIA,
		"get segment reservation from path":     testGetSegmentRsvFromPath,
		"get segment reservation from IF pair":  testGetSegmentRsvsFromIFPair,
		"delete segment reservation":            testDeleteSegmentRsv,
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
	r.Path = segmenttest.NewPathFromComponents(0, "1-ff00:0:1", 1, 1, "1-ff00:0:2", 0)
	r.Indices = segment.Indices{}
	// no indices
	err := db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	require.Equal(t, xtest.MustParseHexString("00000001"), r.ID.Suffix[:])
	rsv, err := db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	// at least one index, and change path
	token := newToken()
	_, err = r.NewIndexFromToken(token, 0, 0)
	require.NoError(t, err)
	r.Path = segmenttest.NewPathFromComponents(1, "1-ff00:0:1", 2, 1, "1-ff00:0:2", 0)
	err = db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	require.Equal(t, xtest.MustParseHexString("00000002"), r.ID.Suffix[:])
	rsv, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	// same path should fail
	err = db.NewSegmentRsv(ctx, r)
	require.Error(t, err)
	// different ASID should start with the lowest suffix
	r = newTestReservation(t)
	r.ID.ASID = xtest.MustParseAS("ff00:1234:1")
	err = db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	require.Equal(t, xtest.MustParseHexString("00000001"), r.ID.Suffix[:])
	rsv, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
}

func testPersistSegmentRsv(ctx context.Context, t *testing.T, db backend.DB) {
	r := newTestReservation(t)
	for i := int64(1); i < 10; i++ {
		_, err := r.NewIndexAtSource(time.Unix(i, 0), 0, 0, 0, 0, reservation.CorePath)
		require.NoError(t, err)
	}
	require.Len(t, r.Indices, 10)
	err := db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	rsv, err := db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	// now remove one index
	err = r.RemoveIndex(0)
	require.NoError(t, err)
	err = db.PersistSegmentRsv(ctx, r)
	require.NoError(t, err)
	rsv, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	// change ID
	r.ID.ASID = xtest.MustParseAS("ff00:1:12")
	copy(r.ID.Suffix[:], xtest.MustParseHexString("beefcafe"))
	err = db.PersistSegmentRsv(ctx, r)
	require.NoError(t, err)
	rsv, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	// change attributes
	r.Ingress = 3
	r.Egress = 4
	r.Path = segmenttest.NewPathFromComponents(3, "1-ff00:0:1", 11, 1, "1-ff00:0:2", 0)
	err = db.PersistSegmentRsv(ctx, r)
	require.NoError(t, err)
	rsv, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	// remove 7 more indices, remains 1 index
	err = r.RemoveIndex(8)
	require.NoError(t, err)
	r.Indices[0].Expiration = time.Unix(12345, 0)
	r.Indices[0].MinBW = 10
	r.Indices[0].MaxBW = 11
	r.Indices[0].AllocBW = 12
	r.Indices[0].Token = newToken() // change the token
	r.Indices[0].Token.BWCls = 8
	err = r.SetIndexConfirmed(r.Indices[0].Idx)
	require.NoError(t, err)
	err = r.SetIndexActive(r.Indices[0].Idx)
	require.NoError(t, err)
	err = db.PersistSegmentRsv(ctx, r)
	require.NoError(t, err)
	rsv, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
}

func testGetSegmentRsvFromID(ctx context.Context, t *testing.T, db backend.DB) {
	r := newTestReservation(t)
	err := db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	// create new index
	expTime := time.Unix(1, 0)
	_, err = r.NewIndexAtSource(expTime, 0, 0, 0, 0, reservation.CorePath)
	require.NoError(t, err)
	err = db.PersistSegmentRsv(ctx, r)
	require.NoError(t, err)
	r2, err := db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, r2)
	// 14 more indices for a total of 16
	require.Len(t, r.Indices, 2)
	for i := 2; i < 16; i++ {
		expTime = time.Unix(int64(i), 0)
		_, err = r.NewIndexAtSource(expTime, reservation.BWCls(i), reservation.BWCls(i),
			reservation.BWCls(i), 0, reservation.CorePath)
		require.NoError(t, err)
	}
	require.Len(t, r.Indices, 16)
	err = db.PersistSegmentRsv(ctx, r)
	require.NoError(t, err)
	r2, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, r2)
	// wrong ID
	ID := r.ID
	ID.ASID++
	r2, err = db.GetSegmentRsvFromID(ctx, &ID)
	require.NoError(t, err)
	require.Nil(t, r2)
}

func testGetSegmentRsvsFromSrcDstIA(ctx context.Context, t *testing.T, db backend.DB) {
	r := newTestReservation(t)
	r.Path = segmenttest.NewPathFromComponents(0, "1-ff00:0:1", 1, 1, "1-ff00:0:2", 0)
	err := db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	rsvs, err := db.GetSegmentRsvsFromSrcDstIA(ctx, r.Path.GetSrcIA(), r.Path.GetDstIA())
	require.NoError(t, err)
	require.Len(t, rsvs, 1)
	require.Equal(t, r, rsvs[0])
	// another reservation with same source and destination
	r2 := newTestReservation(t)
	r2.Path = segmenttest.NewPathFromComponents(0, "1-ff00:0:1", 1, 2, "1-ff00:0:2", 0)
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

func testGetSegmentRsvFromPath(ctx context.Context, t *testing.T, db backend.DB) {
	r1 := newTestReservation(t)
	r1.Path = segmenttest.NewPathFromComponents(0, "1-ff00:0:1", 1, 1, "1-ff00:0:2", 0)
	err := db.NewSegmentRsv(ctx, r1)
	require.NoError(t, err)
	r2 := newTestReservation(t)
	r2.Path = segmenttest.NewPathFromComponents(0, "1-ff00:0:1", 1, 1, "1-ff00:0:3", 0)
	err = db.NewSegmentRsv(ctx, r2)
	require.NoError(t, err)
	// retrieve
	r, err := db.GetSegmentRsvFromPath(ctx, r1.Path)
	require.NoError(t, err)
	require.Equal(t, r1, r)
	r, err = db.GetSegmentRsvFromPath(ctx, r2.Path)
	require.NoError(t, err)
	require.Equal(t, r2, r)
}

func testGetSegmentRsvsFromIFPair(ctx context.Context, t *testing.T, db backend.DB) {
	// insert in1,e1 ; in2,e1 ; in1,e2
	r1 := newTestReservation(t)
	r1.Ingress = 11
	r1.Egress = 12
	err := db.NewSegmentRsv(ctx, r1)
	require.NoError(t, err)
	r2 := newTestReservation(t)
	r2.Ingress = 21
	r2.Egress = 12
	err = db.NewSegmentRsv(ctx, r2)
	require.NoError(t, err)
	r3 := newTestReservation(t)
	r3.Ingress = 11
	r3.Egress = 22
	err = db.NewSegmentRsv(ctx, r3)
	require.NoError(t, err)
	// query with a specific pair
	rsvs, err := db.GetSegmentRsvsFromIFPair(ctx, &r1.Ingress, &r1.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 1)
	expected := []*segment.Reservation{r1}
	require.ElementsMatch(t, expected, rsvs)
	// any ingress
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, nil, &r1.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 2)
	expected = []*segment.Reservation{r1, r2}
	require.ElementsMatch(t, expected, rsvs)
	// any egress
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &r1.Ingress, nil)
	require.NoError(t, err)
	require.Len(t, rsvs, 2)
	expected = []*segment.Reservation{r1, r3}
	require.ElementsMatch(t, expected, rsvs)
	// no matches
	var inexistentIngress common.IFIDType = 222
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &inexistentIngress, nil)
	require.NoError(t, err)
	require.Len(t, rsvs, 0)
	// bad query
	_, err = db.GetSegmentRsvsFromIFPair(ctx, nil, nil)
	require.Error(t, err)
}

func testDeleteSegmentRsv(ctx context.Context, t *testing.T, db backend.DB) {
	r := newTestReservation(t)
	err := db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	err = db.DeleteSegmentRsv(ctx, &r.ID)
	require.NoError(t, err)
	rsv, err := db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Nil(t, rsv)
	// with no indices
	r = newTestReservation(t)
	r.Indices = segment.Indices{}
	err = db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	err = db.DeleteSegmentRsv(ctx, &r.ID)
	require.NoError(t, err)
	rsv, err = db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Nil(t, rsv)
}

// newToken just returns a token that can be serialized. This one has two HopFields.
func newToken() *reservation.Token {
	t, err := reservation.TokenFromRaw(xtest.MustParseHexString(
		"0000000000040500003f001002bad1ce003f001002facade"))
	if err != nil {
		panic("invalid serialized token")
	}
	return t
}

func newTestReservation(t *testing.T) *segment.Reservation {
	t.Helper()
	r := segment.NewReservation()
	r.Path = segment.Path{}
	r.ID.ASID = xtest.MustParseAS("ff00:0:1")
	r.Ingress = 0
	r.Egress = 1
	r.TrafficSplit = 3
	r.PathEndProps = reservation.EndLocal | reservation.StartLocal
	expTime := time.Unix(1, 0)
	_, err := r.NewIndexAtSource(expTime, 1, 3, 2, 5, reservation.CorePath)
	require.NoError(t, err)
	err = r.SetIndexConfirmed(0)
	require.NoError(t, err)
	return r
}
