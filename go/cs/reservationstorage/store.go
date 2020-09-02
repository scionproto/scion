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

package reservationstorage

import (
	"context"

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/cs/reservation/e2e"
	sgt "github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/lib/infra/modules/cleaner"
)

// Store is the interface to interact with the reservation store.
type Store interface {
	AdmitSegmentReservation(ctx context.Context, req *sgt.SetupReq) (
		base.MessageWithPath, error)
	ConfirmSegmentReservation(ctx context.Context, req *sgt.IndexConfirmationReq) (
		base.MessageWithPath, error)
	CleanupSegmentReservation(ctx context.Context, req *sgt.CleanupReq) (
		base.MessageWithPath, error)
	TearDownSegmentReservation(ctx context.Context, req *sgt.TeardownReq) (
		base.MessageWithPath, error)
	AdmitE2EReservation(ctx context.Context, req e2e.SetupRequest) (
		base.MessageWithPath, error)
	CleanupE2EReservation(ctx context.Context, req *e2e.CleanupReq) (
		base.MessageWithPath, error)

	DeleteExpiredIndices(ctx context.Context) (int, error)
}

// TODO(juagargi) there is a number of functions missing: all regarding responses.

// NewIndexCleaner creates a cleaner removing expired indices and reservations.
func NewIndexCleaner(s Store) *cleaner.Cleaner {
	return cleaner.New(func(ctx context.Context) (int, error) {
		return s.DeleteExpiredIndices(ctx)
	}, "colibri")
}
