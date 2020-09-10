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

package e2e

import (
	"time"

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
)

// Request is the base struct for any type of COLIBRI e2e request.
type Request struct {
	base.RequestMetadata                         // information about the request (forwarding path)
	ID                   reservation.E2EID       // the ID this request refers to
	Index                reservation.IndexNumber // the index this request refers to
	Timestamp            time.Time               // the mandatory timestamp
}

// NewRequest constructs the e2e Request type.
func NewRequest(ts time.Time, id *reservation.E2EID, idx reservation.IndexNumber,
	path *spath.Path) (*Request, error) {

	metadata, err := base.NewRequestMetadata(path)
	if err != nil {
		return nil, serrors.WrapStr("new segment request", err)
	}

	if id == nil {
		return nil, serrors.New("new e2e request with nil ID")
	}

	return &Request{
		RequestMetadata: *metadata,
		ID:              *id,
		Index:           idx,
		Timestamp:       ts,
	}, nil
}

// SetupReq is an e2e setup/renewal request, that has been so far accepted.
type SetupReq struct {
	Request
	SegmentRsvs     []reservation.SegmentID
	RequestedBW     reservation.BWCls
	AllocationTrail []reservation.BWCls
}

// SetupReqSuccess is a successful e2e setup request traveling along the reservation path.
type SetupReqSuccess struct {
	SetupReq
	Token reservation.Token
}

// SetupReqFailure is a failed e2e setup request also traveling along the reservation path.
type SetupReqFailure struct {
	SetupReq
	ErrorCode uint8
}

// CleanupReq is a cleaup request for an e2e index.
type CleanupReq struct {
	Request
}
