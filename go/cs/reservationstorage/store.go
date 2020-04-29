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

	"github.com/scionproto/scion/go/cs/reservation/e2e"
	sgt "github.com/scionproto/scion/go/cs/reservation/segment"
	rsv "github.com/scionproto/scion/go/lib/colibri/reservation"
)

// Store is the interface to interact with the reservation store.
type Store interface {
	AdmitSegmentReservation(ctx context.Context, req sgt.SetupReq) error
	ConfirmSegmentReservation(ctx context.Context, id rsv.SegmentID, idx sgt.IndexID) error
	CleanupSegmentReservation(ctx context.Context, id rsv.SegmentID, idx sgt.IndexID) error
	TearDownSegmentReservation(ctx context.Context, id rsv.SegmentID, idx sgt.IndexID) error
	AdmitE2EReservation(ctx context.Context, req e2e.SetupReq) error
	CleanupE2EReservation(ctx context.Context, id rsv.E2EID, idx sgt.IndexID) error
}
