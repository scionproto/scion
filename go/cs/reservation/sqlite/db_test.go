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

package sqlite

import (
	"context"
	"testing"

	"github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/reservation/reservationdbtest"
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/xtest"
)

type TestDB struct {
	*Backend
}

func (b *TestDB) Prepare(t *testing.T, _ context.Context) {
	b.Backend = newDB(t)
}

func TestReservationDBSuite(t *testing.T) {
	db := &TestDB{}
	reservationdbtest.TestDB(t, db)
}

func TestNewSuffix(t *testing.T) {
	ctx := context.Background()
	asid := xtest.MustParseAS("ff00:0:1")
	db := newDB(t)
	suffix, err := newSuffix(ctx, db.db, asid)
	require.NoError(t, err)
	require.Equal(t, uint32(1), suffix)
	// add reservations
	addSegRsvRows(t, db, asid, 3, 5)
	suffix, err = newSuffix(ctx, db.db, asid)
	require.NoError(t, err)
	require.Equal(t, uint32(1), suffix)
	addSegRsvRows(t, db, asid, 1, 2)
	suffix, err = newSuffix(ctx, db.db, asid)
	require.NoError(t, err)
	require.Equal(t, uint32(6), suffix)
}

func TestRaceForSuffix(t *testing.T) {
	ctx := context.Background()
	asid := xtest.MustParseAS("ff00:0:1")
	db := newDB(t)
	addSegRsvRows(t, db, asid, 1, 2)
	suffix1, err := newSuffix(ctx, db.db, asid)
	require.NoError(t, err)
	require.Equal(t, uint32(3), suffix1)
	suffix2, err := newSuffix(ctx, db.db, asid)
	require.NoError(t, err)
	require.Equal(t, uint32(3), suffix2)
	rsv := &segment.Reservation{
		ID:      reservation.SegmentID{ASID: asid},
		Indices: segment.Indices{segment.Index{}},
	}
	err = insertNewSegReservation(ctx, db.db, rsv, suffix1)
	require.NoError(t, err)
	err = insertNewSegReservation(ctx, db.db, rsv, suffix2)
	require.Error(t, err)
	sqliteError, ok := err.(sqlite3.Error)
	require.True(t, ok)
	require.Equal(t, sqlite3.ErrConstraint, sqliteError.Code)
}

func BenchmarkNewSuffix10K(b *testing.B)  { benchmarkNewSuffix(b, 10000) }
func BenchmarkNewSuffix100K(b *testing.B) { benchmarkNewSuffix(b, 100000) }
func BenchmarkNewSuffix1M(b *testing.B)   { benchmarkNewSuffix(b, 1000000) }

func newDB(t testing.TB) *Backend {
	t.Helper()
	db, err := New("file::memory:")
	require.NoError(t, err)
	return db
}

func addSegRsvRows(t testing.TB, b *Backend, asid addr.AS, firstSuffix, lastSuffix uint32) {
	t.Helper()
	ctx := context.Background()
	query := `INSERT INTO seg_reservation (id_as, id_suffix, ingress, egress, path,
		end_props, traffic_split, src_ia, dst_ia, active_index)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, -1)`
	for suffix := firstSuffix; suffix <= lastSuffix; suffix++ {
		_, err := b.db.ExecContext(ctx, query, asid, suffix, 0, 0, nil, 0, 0, nil, nil)
		require.NoError(t, err)
	}
}

func benchmarkNewSuffix(b *testing.B, entries uint32) {
	db := newDB(b)
	ctx := context.Background()
	asid := xtest.MustParseAS("ff00:0:1")
	addSegRsvRows(b, db, asid, 1, entries)
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		suffix, err := newSuffix(ctx, db.db, asid)
		require.NoError(b, err)
		require.Equal(b, entries+1, suffix)
	}
}
