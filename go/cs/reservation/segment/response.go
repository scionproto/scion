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

package segment

import (
	"time"

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Response is the base struct for any type of COLIBRI segment response.
type Response struct {
	base.RequestMetadata                         // information about the request (forwarding path)
	ID                   reservation.SegmentID   // the ID this request refers to
	Index                reservation.IndexNumber // the index this request refers to
	Accepted             bool                    // success or failure type of response
	FailedHop            uint8                   // if accepted is false, the AS that failed it
}

var _ base.MessageWithPath = (*Response)(nil)

// NewResponse contructs the segment Response type.
func NewResponse(ts time.Time, id *reservation.SegmentID, idx reservation.IndexNumber,
	path base.ColibriPath, accepted bool, failedHop uint8) (*Response, error) {

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
type ResponseSetupFailure struct {
	Response
	FailedSetup *SetupReq
}

// ResponseTeardownSuccess is sent by the last AS in the reverse path.
type ResponseTeardownSuccess struct {
	Response
}

// ResponseTeardownFailure is sent in the reverse path.
type ResponseTeardownFailure struct {
	Response
	ErrorCode uint8
}

// ResponseIndexConfirmationSuccess is a successful index confirmation. The target state is
// echoed in the response.
type ResponseIndexConfirmationSuccess struct {
	Response
	State IndexState
}

// ResponseIndexConfirmationFailure is a failed index confirmation.
type ResponseIndexConfirmationFailure struct {
	Response
	ErrorCode uint8
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
