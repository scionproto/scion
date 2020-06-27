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
	"time"

	"github.com/scionproto/scion/go/cs/reservation/e2e"
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
)

// ReserverOnly has the methods available to the AS that starts the reservation.
type ReserverOnly interface {
	// GetSegmentRsvFromSrcDstAS returns all reservations that start at src AS and end in dst AS.
	GetSegmentRsvFromSrcDstAS(ctx context.Context, srcIA, dstIA addr.IA) (
		[]*segment.Reservation, error)
	// GetSegmentRsvFromPath searches for a segment reservation with the specified path.
	GetSegmentRsvFromPath(ctx context.Context, path *segment.Path) (
		*segment.Reservation, error)

	// NewSegmentRsv creates a new segment reservation in the DB, with an unused reservation ID.
	// The created ID is set in the reservation pointer argument. Used by setup req.
	NewSegmentRsv(ctx context.Context, rsv *segment.Reservation) error
}

// TransitOnly represents an AS in-path of a reservation, not the one originating it.
type TransitOnly interface {
	// GetSegmentRsvsFromIFPair returns all segment reservations that enter this AS at
	// the specified ingress and exit at that egress. Used by setup req.
	GetSegmentRsvsFromIFPair(ctx context.Context, ingress, egress common.IFIDType) (
		[]*segment.Reservation, error)
}

// ReserverAndTransit contains the functionality for any AS that has a COLIBRI service.
type ReserverAndTransit interface {
	// GetSegmentRsvFromID will return the reservation with that ID.
	// If an IndexNumber is specified it will populate its indices only with that one.
	// If the ID is not found, or the index (if specified) is not found, an error will be returned.
	// Used by setup/renew req/resp. and any request.
	GetSegmentRsvFromID(ctx context.Context, ID reservation.SegmentID,
		idx *reservation.IndexNumber) (*segment.Reservation, error)
	// SetActiveIndex updates the active index. Used in index confirmation.
	SetSegmentActiveIndex(ctx context.Context, rsv segment.Reservation,
		idx reservation.IndexNumber) error
	// NewSegmentRsvIndex stores a new index for a segment reservation. Used in setup/renew.
	NewSegmentIndex(ctx context.Context, rsv *segment.Reservation,
		idx reservation.IndexNumber) error
	// UpdateSegmentRsvIndex updates an index of a segment rsv. Used in setup/renew response.
	UpdateSegmentIndex(ctx context.Context, rsv *segment.Reservation,
		idx reservation.IndexNumber) error
	// DeleteSegmentIndex removes the index from the DB. Used in cleanup.
	DeleteSegmentIndex(ctx context.Context, rsv *segment.Reservation,
		idx reservation.IndexNumber) error
	// DeleteSegmentRsv removes the segment reservation. Used in teardown.
	DeleteSegmentRsv(ctx context.Context, ID reservation.SegmentID) error

	// DeleteExpiredIndices will remove expired indices from the DB. If a reservation is left
	// without any index after removing the expired ones, it will also be removed.
	// Used on schedule.
	DeleteExpiredIndices(ctx context.Context, now time.Time) (int, error)

	// GetE2ERsvFromID finds the end to end resevation given its ID.
	GetE2ERsvFromID(ctx context.Context, ID reservation.E2EID, idx reservation.IndexNumber) (
		*e2e.Reservation, error)
	// NewE2EIndex stores a new index in the DB.
	// If the e2e reservation does not exist, it is created.
	NewE2EIndex(ctx context.Context, rsv *e2e.Reservation, idx reservation.IndexNumber) error
	// UpdateE2EIndex updates the token in an index of the e2e reservation.
	UpdateE2EIndex(ctx context.Context, rsv *e2e.Reservation, idx reservation.IndexNumber) error
	// DeleteE2EIndex removes an e2e index. It is used in the cleanup process.
	DeleteE2EIndex(ctx context.Context, rsv *e2e.Reservation, idx reservation.IndexNumber) error
}

type Transaction interface {
	ReserverOnly
	TransitOnly
	ReserverAndTransit
	Commit() error
	Rollback() error
}

// DB is the interface for any reservation backend.
type DB interface {
	BeginTransaction(ctx context.Context, opts *sql.TxOptions) (Transaction, error)
	ReserverOnly
	TransitOnly
	ReserverAndTransit
	db.LimitSetter
	io.Closer
}
