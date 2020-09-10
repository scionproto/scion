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
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/reservation/e2e"
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/cs/reservation/segmenttest"
	"github.com/scionproto/scion/go/cs/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

type TestableDB interface {
	backend.DB
	Prepare(*testing.T, context.Context)
}

func TestDB(t *testing.T, db TestableDB) {
	tests := map[string]func(context.Context, *testing.T, backend.DB){
		"insert segment reservations create ID":  testNewSegmentRsv,
		"persist segment reservation":            testPersistSegmentRsv,
		"get segment reservation from ID":        testGetSegmentRsvFromID,
		"get segment reservations from src/dst":  testGetSegmentRsvsFromSrcDstIA,
		"get segment reservation from path":      testGetSegmentRsvFromPath,
		"get all segment reservations":           testGetAllSegmentRsvs,
		"get segment reservation from IF pair":   testGetSegmentRsvsFromIFPair,
		"delete segment reservation":             testDeleteSegmentRsv,
		"delete expired indices":                 testDeleteExpiredIndices,
		"persist e2e reservation":                testPersistE2ERsv,
		"get e2e reservation from ID":            testGetE2ERsvFromID,
		"get e2e reservations from segment ones": testGetE2ERsvsOnSegRsv,
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
	for i := uint32(1); i < 10; i++ {
		_, err := r.NewIndexAtSource(util.SecsToTime(i), 0, 0, 0, 0, reservation.CorePath)
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
	r.Indices[0].Expiration = util.SecsToTime(12345)
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
	expTime := util.SecsToTime(1)
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
		expTime = util.SecsToTime(uint32(i))
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

func testGetAllSegmentRsvs(ctx context.Context, t *testing.T, db backend.DB) {
	// empty
	rsvs, err := db.GetAllSegmentRsvs(ctx)
	require.NoError(t, err)
	require.Empty(t, rsvs)
	// insert in1,eg1 ; in2,eg1 ; in1,eg2
	r1 := newTestReservation(t)
	r1.Ingress = 11
	r1.Egress = 12
	err = db.NewSegmentRsv(ctx, r1)
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
	// retrieve them
	rsvs, err = db.GetAllSegmentRsvs(ctx)
	require.NoError(t, err)
	expected := []*segment.Reservation{r1, r2, r3}
	require.ElementsMatch(t, expected, rsvs)
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

func testDeleteExpiredIndices(ctx context.Context, t *testing.T, db backend.DB) {
	// create seg. and e2e reservations that have indices expiring at different times.
	// rX stands for segment rsv. and eX for an e2e. Twice the same symbol means another index.
	// timeline: e1...r1...r2,r3...e2,e3...e3,e4...r3,r4...e5
	//            1    2       3       4       5       6    1000
	// Each eX is linked to a rX, being X the same for both. But e5 is linked to r4.

	// r1, e1
	segIds := make([]reservation.SegmentID, 0)
	r := newTestReservation(t)
	r.Indices[0].Expiration = util.SecsToTime(2)
	err := db.NewSegmentRsv(ctx, r) // save r1
	require.NoError(t, err)
	segIds = append(segIds, r.ID)
	e := newTestE2EReservation(t)
	e.ID.ASID = xtest.MustParseAS("ff00:0:1")
	e.SegmentReservations = []*segment.Reservation{r}
	e.Indices[0].Expiration = util.SecsToTime(1)
	err = db.PersistE2ERsv(ctx, e) // save e1
	require.NoError(t, err)
	// r2, e2
	r.Indices[0].Expiration = util.SecsToTime(3)
	err = db.NewSegmentRsv(ctx, r) // save r2
	require.NoError(t, err)
	segIds = append(segIds, r.ID)
	e.ID.ASID = xtest.MustParseAS("ff00:0:2")
	e.SegmentReservations = []*segment.Reservation{r}
	e.Indices[0].Expiration = util.SecsToTime(4)
	err = db.PersistE2ERsv(ctx, e) // save e2
	require.NoError(t, err)
	// r3, e3
	r.Indices[0].Expiration = util.SecsToTime(3)
	r.NewIndexAtSource(util.SecsToTime(6), 1, 3, 2, 5, reservation.CorePath)
	err = db.NewSegmentRsv(ctx, r) // save r3
	require.NoError(t, err)
	segIds = append(segIds, r.ID)
	e.ID.ASID = xtest.MustParseAS("ff00:0:3")
	e.SegmentReservations = []*segment.Reservation{r}
	e.Indices[0].Expiration = util.SecsToTime(4)
	_, err = e.NewIndex(util.SecsToTime(5))
	require.NoError(t, err)
	err = db.PersistE2ERsv(ctx, e) // save e3
	require.NoError(t, err)
	// r4, e4
	r.Indices = r.Indices[:1]
	r.Indices[0].Expiration = util.SecsToTime(6)
	err = db.NewSegmentRsv(ctx, r) // save r4
	require.NoError(t, err)
	segIds = append(segIds, r.ID)
	e.Indices = e.Indices[:1]
	e.Indices[0].Expiration = util.SecsToTime(5)
	e.ID.ASID = xtest.MustParseAS("ff00:0:4")
	e.SegmentReservations = []*segment.Reservation{r}
	err = db.PersistE2ERsv(ctx, e) // save e4
	require.NoError(t, err)
	// e5
	e.ID.ASID = xtest.MustParseAS("ff00:0:5")
	e.SegmentReservations = []*segment.Reservation{r}
	e.Indices[0].Expiration = util.SecsToTime(1000)
	err = db.PersistE2ERsv(ctx, e) // save e5
	require.NoError(t, err)

	// second 1: nothing deleted
	c, err := db.DeleteExpiredIndices(ctx, util.SecsToTime(1))
	require.NoError(t, err)
	require.Equal(t, 0, c)
	rsvs, err := db.GetSegmentRsvsFromIFPair(ctx, &r.Ingress, &r.Egress) // get all seg rsvs
	require.NoError(t, err)
	require.Len(t, rsvs, 4)
	e2es := getAllE2ERsvsOnSegmentRsvs(ctx, t, db, segIds)
	require.Len(t, e2es, 5)
	// second 2, in DB: r1...r2,r3...e2,e3...e3,e4...r3,r4...e5
	c, err = db.DeleteExpiredIndices(ctx, util.SecsToTime(2))
	require.NoError(t, err)
	require.Equal(t, 1, c)
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &r.Ingress, &r.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 4)
	e2es = getAllE2ERsvsOnSegmentRsvs(ctx, t, db, segIds)
	require.Len(t, e2es, 4)
	// second 3: in DB: r2,r3...e2,e3...e3,e4...r3,r4...e5
	c, err = db.DeleteExpiredIndices(ctx, util.SecsToTime(3))
	require.NoError(t, err)
	require.Equal(t, 1, c)
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &r.Ingress, &r.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 3)
	e2es = getAllE2ERsvsOnSegmentRsvs(ctx, t, db, segIds)
	require.Len(t, e2es, 4)
	// second 4: in DB: e2,e3...e3,e4...r3,r4...e5
	c, err = db.DeleteExpiredIndices(ctx, util.SecsToTime(4))
	require.NoError(t, err)
	require.Equal(t, 2, c)
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &r.Ingress, &r.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 2)
	e2es = getAllE2ERsvsOnSegmentRsvs(ctx, t, db, segIds)
	require.Len(t, e2es, 3) // r2 is gone, cascades for e2
	// second 5: in DB: e3,e4...r3,r4...e5
	c, err = db.DeleteExpiredIndices(ctx, util.SecsToTime(5))
	require.NoError(t, err)
	require.Equal(t, 2, c)
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &r.Ingress, &r.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 2)
	e2es = getAllE2ERsvsOnSegmentRsvs(ctx, t, db, segIds)
	require.Len(t, e2es, 3)
	// second 6: in DB: r3,r4...e5
	c, err = db.DeleteExpiredIndices(ctx, util.SecsToTime(6))
	require.NoError(t, err)
	require.Equal(t, 2, c)
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &r.Ingress, &r.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 2)
	e2es = getAllE2ERsvsOnSegmentRsvs(ctx, t, db, segIds)
	require.Len(t, e2es, 1)
	// second 7, in DB: nothing
	c, err = db.DeleteExpiredIndices(ctx, util.SecsToTime(7))
	require.NoError(t, err)
	require.Equal(t, 2, c)
	rsvs, err = db.GetSegmentRsvsFromIFPair(ctx, &r.Ingress, &r.Egress)
	require.NoError(t, err)
	require.Len(t, rsvs, 0)
	e2es = getAllE2ERsvsOnSegmentRsvs(ctx, t, db, segIds)
	require.Len(t, e2es, 0) // r4 is gone, cascades for e5
}

func testPersistE2ERsv(ctx context.Context, t *testing.T, db backend.DB) {
	r1 := newTestE2EReservation(t)
	for _, seg := range r1.SegmentReservations {
		err := db.PersistSegmentRsv(ctx, seg)
		require.NoError(t, err)
	}
	err := db.PersistE2ERsv(ctx, r1)
	require.NoError(t, err)
	// get it back
	rsv, err := db.GetE2ERsvFromID(ctx, &r1.ID)
	require.NoError(t, err)
	require.Equal(t, r1, rsv)
	// modify
	r2 := rsv
	for i := range r2.ID.Suffix {
		r2.ID.Suffix[i] = byte(i)
	}
	for i := uint32(2); i < 16; i++ { // add 14 more indices
		_, err = r2.NewIndex(util.SecsToTime(i))
		require.NoError(t, err)
	}
	for i := 0; i < 2; i++ {
		seg := newTestReservation(t)
		seg.ID.ASID = xtest.MustParseAS(fmt.Sprintf("ff00:2:%d", i+1))
		for j := uint32(1); j < 16; j++ {
			_, err := seg.NewIndexAtSource(util.SecsToTime(j), 1, 3, 2, 5, reservation.CorePath)
			require.NoError(t, err)
		}
		err := db.PersistSegmentRsv(ctx, seg)
		require.NoError(t, err)
		r2.SegmentReservations = append(r2.SegmentReservations, seg)
	}
	err = db.PersistE2ERsv(ctx, r2)
	require.NoError(t, err)
	rsv, err = db.GetE2ERsvFromID(ctx, &r2.ID)
	require.NoError(t, err)
	require.Equal(t, r2, rsv)
	// check the other reservation was left intact
	rsv, err = db.GetE2ERsvFromID(ctx, &r1.ID)
	require.NoError(t, err)
	require.Equal(t, r1, rsv)
	// try to persist an e2e reservation without persisting its associated segment reservation
	r := newTestE2EReservation(t)
	r.SegmentReservations[0].ID.ASID = xtest.MustParseAS("ff00:3:1")
	err = db.PersistE2ERsv(ctx, r)
	require.Error(t, err)
	// after persisting the segment one, it will work
	err = db.PersistSegmentRsv(ctx, r.SegmentReservations[0])
	require.NoError(t, err)
	err = db.PersistE2ERsv(ctx, r)
	require.NoError(t, err)
}

func testGetE2ERsvFromID(ctx context.Context, t *testing.T, db backend.DB) {
	// create several e2e reservations, with one segment reservations in common, and two not
	checkThisRsvs := map[int]*e2e.Reservation{1: nil, 16: nil, 50: nil, 100: nil}
	for i := 1; i <= 100; i++ {
		r := newTestE2EReservation(t)
		binary.BigEndian.PutUint32(r.ID.Suffix[:], uint32(i))
		_, found := checkThisRsvs[i]
		if found {
			checkThisRsvs[i] = r
		}
		for j := 0; j < 2; j++ {
			seg := newTestReservation(t)
			seg.ID.ASID = xtest.MustParseAS(fmt.Sprintf("ff00:%d:%d", i, j+1))
			err := db.PersistSegmentRsv(ctx, seg)
			require.NoError(t, err)
		}
		for _, seg := range r.SegmentReservations {
			segRsv, err := db.GetSegmentRsvFromID(ctx, &seg.ID)
			require.NoError(t, err)
			if segRsv == nil {
				err := db.PersistSegmentRsv(ctx, seg)
				require.NoError(t, err)
			}
		}
		err := db.PersistE2ERsv(ctx, r)
		require.NoError(t, err)
	}
	// now check
	for i, r := range checkThisRsvs {
		ID := reservation.E2EID{ASID: xtest.MustParseAS("ff00:0:1")}
		binary.BigEndian.PutUint32(ID.Suffix[:], uint32(i))
		rsv, err := db.GetE2ERsvFromID(ctx, &ID)
		require.NoError(t, err)
		require.Equal(t, r, rsv)
	}
	// with 8 indices starting at index number 14
	r := newTestE2EReservation(t)
	r.Indices = e2e.Indices{}
	for i := uint32(2); i < 18; i++ {
		_, err := r.NewIndex(util.SecsToTime(i / 2))
		require.NoError(t, err)
	}
	r.Indices = r.Indices[14:]
	for i := uint32(18); i < 20; i++ {
		_, err := r.NewIndex(util.SecsToTime(i / 2))
		require.NoError(t, err)
	}
	err := db.PersistE2ERsv(ctx, r)
	require.NoError(t, err)
	rsv, err := db.GetE2ERsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
	// 16 indices
	require.Len(t, r.Indices, 4)
	for i := uint32(20); i < 32; i++ {
		_, err := r.NewIndex(util.SecsToTime(i / 2))
		require.NoError(t, err)
	}
	require.Len(t, r.Indices, 16)
	err = db.PersistE2ERsv(ctx, r)
	require.NoError(t, err)
	rsv, err = db.GetE2ERsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, rsv)
}

func testGetE2ERsvsOnSegRsv(ctx context.Context, t *testing.T, db backend.DB) {
	s1 := newTestReservation(t)
	err := db.NewSegmentRsv(ctx, s1)
	require.NoError(t, err)
	s2 := newTestReservation(t)
	err = db.NewSegmentRsv(ctx, s2)
	require.NoError(t, err)
	// e2e reservations
	e1 := newTestE2EReservation(t)
	e1.ID.ASID = xtest.MustParseAS("ff00:0:1")
	e1.SegmentReservations = []*segment.Reservation{s1}
	err = db.PersistE2ERsv(ctx, e1)
	require.NoError(t, err)
	e2 := newTestE2EReservation(t)
	e2.ID.ASID = xtest.MustParseAS("ff00:0:2")
	e2.SegmentReservations = []*segment.Reservation{s2}
	err = db.PersistE2ERsv(ctx, e2)
	require.NoError(t, err)
	e3 := newTestE2EReservation(t)
	e3.ID.ASID = xtest.MustParseAS("ff00:0:3")
	e3.SegmentReservations = []*segment.Reservation{s1, s2}
	err = db.PersistE2ERsv(ctx, e3)
	require.NoError(t, err)
	// test
	rsvs, err := db.GetE2ERsvsOnSegRsv(ctx, &s1.ID)
	require.NoError(t, err)
	require.ElementsMatch(t, rsvs, []*e2e.Reservation{e1, e3})
	rsvs, err = db.GetE2ERsvsOnSegRsv(ctx, &s2.ID)
	require.NoError(t, err)
	require.ElementsMatch(t, rsvs, []*e2e.Reservation{e2, e3})
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
	expTime := util.SecsToTime(1)
	_, err := r.NewIndexAtSource(expTime, 1, 3, 2, 5, reservation.CorePath)
	require.NoError(t, err)
	err = r.SetIndexConfirmed(0)
	require.NoError(t, err)
	return r
}

func newTestE2EReservation(t *testing.T) *e2e.Reservation {
	rsv := &e2e.Reservation{
		ID: reservation.E2EID{
			ASID: xtest.MustParseAS("ff00:0:1"),
		},
		SegmentReservations: []*segment.Reservation{
			newTestReservation(t),
		},
	}
	expTime := util.SecsToTime(1)
	_, err := rsv.NewIndex(expTime)
	require.NoError(t, err)
	return rsv
}

func getAllE2ERsvsOnSegmentRsvs(ctx context.Context, t *testing.T, db backend.DB,
	ids []reservation.SegmentID) []*e2e.Reservation {

	set := make(map[string]struct{})
	rsvs := make([]*e2e.Reservation, 0)
	for _, id := range ids {
		rs, err := db.GetE2ERsvsOnSegRsv(ctx, &id)
		require.NoError(t, err)
		for _, r := range rs {
			s := hex.EncodeToString(r.ID.ToRaw())
			_, found := set[s]
			if !found {
				rsvs = append(rsvs, r)
				set[s] = struct{}{}
			}
		}
	}
	return rsvs
}
