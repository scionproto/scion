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

// Response is the base struct for any type of COLIBRI e2e response.
type Response struct {
	base.RequestMetadata                         // information about the request (forwarding path)
	ID                   reservation.E2EID       // the ID this request refers to
	Index                reservation.IndexNumber // the index this request refers to
	Accepted             bool                    // success or failure type of response
	FailedHop            uint8                   // if accepted is false, the AS that failed it
}

// NewResponse contructs the segment Response type.
func NewResponse(ts time.Time, id *reservation.E2EID, idx reservation.IndexNumber,
	path *spath.Path, accepted bool, failedHop uint8) (*Response, error) {

	metadata, err := base.NewRequestMetadata(path)
	if err != nil {
		return nil, serrors.WrapStr("new segment request", err)
	}
	if id == nil {
		return nil, serrors.New("new segment response with nil ID")
	}
	return &Response{
		RequestMetadata: *metadata,
		ID:              *id,
		Index:           reservation.IndexNumber(idx),
		Accepted:        accepted,
		FailedHop:       failedHop,
	}, nil
}

// ResponseSetupSuccess is the response to a success setup. It's sent on the reverse direction.
type ResponseSetupSuccess struct {
	Response
	Token reservation.Token
}

// ResponseSetupFailure is the response to a failed setup. It's sent on the reverse direction.
// The failed hop is the length of MaxBWs + 1.
type ResponseSetupFailure struct {
	Response
	ErrorCode uint8
	InfoField reservation.InfoField
	MaxBWs    []reservation.BWCls // granted by ASes in the path until the failed hop
}

// ResponseCleanupSuccess is a response to a successful cleanup request.
type ResponseCleanupSuccess struct {
	Response
}

// ResponseCleanupFailure is a failed index cleanup.
type ResponseCleanupFailure struct {
	Response
	ErrorCode uint8
}
