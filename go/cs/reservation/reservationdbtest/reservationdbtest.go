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
		"insert segment index":                  testNewSegmentIndex,
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
	r := segment.NewReservation()
	r.Egress = 1
	r.Path = segmenttest.NewPathFromComponents(0, "1-ff00:0:1", 1, 1, "1-ff00:0:2", 0)
	r.ID.ASID = xtest.MustParseAS("ff00:0:1")
	expTime := time.Unix(1, 0)
	token := newToken()
	r.NewIndex(expTime, *token)
	err := db.NewSegmentRsv(ctx, r)
	require.NoError(t, err)
	require.Equal(t, xtest.MustParseHexString("00000001"), r.ID.Suffix[:])
}

func testNewSegmentIndex(ctx context.Context, t *testing.T, db backend.DB) {
	r := segment.NewReservation()
	r.EgressIFID = 1
	p := segmenttest.NewPathFromComponents(0, "1-ff00:0:1", 1, 1, "1-ff00:0:2", 0)
	r.Path = &p
	r.ID.ASID = xtest.MustParseAS("ff00:0:1")
	db.NewSegmentRsv(ctx, r)
	expTime := time.Unix(1, 0)
	idx, err := r.NewIndex(expTime, *newToken())
	require.NoError(t, err)

	err = db.NewSegmentIndex(ctx, r, idx)
	require.NoError(t, err)
	r2, err := db.GetSegmentRsvFromID(ctx, &r.ID)
	require.NoError(t, err)
	require.Equal(t, r, r2)
}

func testGetSegmentRsvFromID(t *testing.T, db backend.DB) {

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
