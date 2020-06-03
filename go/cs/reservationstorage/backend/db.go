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

package backend

import (
	"context"
	"database/sql"
	"io"

	"github.com/scionproto/scion/go/cs/reservation/e2e"
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
)

type SegmentRead interface {
	// GetSegmentRsvFromID will return the reservation with that ID.
	// If an IndexNumber is specified it will populate its indices with that one.
	// If the ID is not found, or the index (if specified) is not found, an error will be returned.
	GetSegmentRsvFromID(ctx context.Context, ID reservation.SegmentID,
		idx *reservation.IndexNumber) (*segment.Reservation, error)
	// GetSegmentRsvFromSrcDstAS returns all reservations that start at src AS and end in dst AS.
	GetSegmentRsvFromSrcDstAS(ctx context.Context, srcAS, dstAS addr.IA) (
		[]*segment.Reservation, error)
	// GetSegmentRsvFromPath searches for a segment reservation with the specified path.
	GetSegmentRsvFromPath(ctx context.Context, path *segment.Path) (
		*segment.Reservation, error)
	// GetSegmentRsvsFromIFPair returns all segment reservations that enter this AS at
	// the specified ingress and exit at that egress.
	GetSegmentRsvsFromIFPair(ctx context.Context, ingress, egress common.IFIDType) (
		[]*segment.Reservation, error)
}

type SegmentWrite interface {
	// NewSegmentRsv creates a new segment reservation in the DB, with an unused reservation ID.
	// The created ID is set in the reservation pointer argument.
	NewSegmentRsv(ctx context.Context, rsv *segment.Reservation) error
	// SetActiveIndex updates the active index for the segment reservation.
	SetSegmentActiveIndex(ctx context.Context, rsv segment.Reservation,
		idx reservation.IndexNumber) error
	// NewSegmentRsvIndex stores a new index for a segment reservation.
	NewSegmentIndex(ctx context.Context, rsv *segment.Reservation,
		idx reservation.IndexNumber) error
	// UpdateSegmentRsvIndex updates an index of a segment reservation.
	UpdateSegmentIndex(ctx context.Context, rsv *segment.Reservation,
		idx reservation.IndexNumber) error
	// DeleteExpiredIndices removes the index from the DB. Used in cleanup.
	DeleteSegmentIndex(ctx context.Context, rsv *segment.Reservation,
		idx reservation.IndexNumber) error

	// DeleteExpiredIndices will remove expired indices from the DB. If a reservation is left
	// without any index after removing the expired ones, it will also be removed.
	DeleteExpiredIndices(ctx context.Context) (int, error)
	// DeleteExpiredIndices removes the segment reservation
	DeleteSegmentRsv(ctx context.Context, ID reservation.SegmentID) error
}

type E2ERead interface {
	// GetE2ERsvFromID finds the end to end resevation given its ID.
	GetE2ERsvFromID(ctx context.Context, ID reservation.E2EID, idx reservation.IndexNumber) (
		*e2e.Reservation, error)
}

type E2EWrite interface {
	// NewE2EIndex stores a new index in the DB.
	// If the e2e reservation does not exist, it is created.
	NewE2EIndex(ctx context.Context, rsv *e2e.Reservation, idx reservation.IndexNumber) error
	// UpdateE2EIndex updates the token in an index of the e2e reservation.
	UpdateE2EIndex(ctx context.Context, rsv *e2e.Reservation, idx reservation.IndexNumber) error
	// DeleteE2EIndex removes an e2e index. It is used in the cleanup process.
	DeleteE2EIndex(ctx context.Context, rsv *e2e.Reservation, idx reservation.IndexNumber) error
}

// DBRead specifies the read operations a reservation storage must have.
type DBRead interface {
	SegmentRead
	E2ERead
}

// DBWrite specifies the write operations a reservation storage must have.
type DBWrite interface {
	SegmentWrite
	E2EWrite
}

type Transaction interface {
	DBRead
	DBWrite
	Commit() error
	Rollback() error
}

// DB is the interface for any reservation backend.
type DB interface {
	BeginTransaction(ctx context.Context, opts *sql.TxOptions) (Transaction, error)
	db.LimitSetter
	io.Closer
}
