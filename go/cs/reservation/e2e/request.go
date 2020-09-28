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

// SetupRequest represents all possible e2e setup requests.
type SetupRequest interface {
	IsSuccessful() bool
	GetCommonSetupReq() *SetupReq // return the underlying basic SetupReq (common for all)
}

// SetupReq is an e2e setup/renewal request, that has been so far accepted.
type SetupReq struct {
	Request
	SegmentRsvs              []reservation.SegmentID
	SegmentRsvASCount        []uint8 // how many ASes per segment reservation
	RequestedBW              reservation.BWCls
	AllocationTrail          []reservation.BWCls
	totalASCount             int
	currentASSegmentRsvIndex int // the index in SegmentRsv for the current AS
	isTransfer               bool
}

// NewSetupRequest creates and initializes an e2e setup request common for both success and failure.
func NewSetupRequest(r *Request, segRsvs []reservation.SegmentID, segRsvCount []uint8,
	requestedBW reservation.BWCls, allocTrail []reservation.BWCls) (*SetupReq, error) {

	if len(segRsvs) != len(segRsvCount) || len(segRsvs) == 0 {
		return nil, serrors.New("e2e setup request invalid", "seg_rsv_len", len(segRsvs),
			"seg_rsv_count_len", len(segRsvCount))
	}
	totalASCount := 0
	currASindex := -1
	isTransfer := false
	n := len(allocTrail) - 1
	for i, c := range segRsvCount {
		totalASCount += int(c)
		n -= int(c) - 1
		if i == len(segRsvCount)-1 {
			n-- // the last segment spans 1 more AS
		}
		if n < 0 && currASindex < 0 {
			currASindex = i
			isTransfer = i < len(segRsvCount)-1 && n == -1 // dst AS is no transfer
		}
	}
	totalASCount -= len(segRsvCount) - 1
	if currASindex < 0 {
		return nil, serrors.New("error initializing e2e request",
			"alloc_trail_len", len(allocTrail), "seg_rsv_count", segRsvCount)
	}
	return &SetupReq{
		Request:                  *r,
		SegmentRsvs:              segRsvs,
		SegmentRsvASCount:        segRsvCount,
		RequestedBW:              requestedBW,
		AllocationTrail:          allocTrail,
		totalASCount:             totalASCount,
		currentASSegmentRsvIndex: currASindex,
		isTransfer:               isTransfer,
	}, nil
}

// GetCommonSetupReq returns the pointer to the data structure.
func (r *SetupReq) GetCommonSetupReq() *SetupReq {
	return r
}

func (r *SetupReq) Transfer() bool {
	return r.isTransfer
}

type PathLocation int

const (
	Source PathLocation = iota
	Transit
	Destination
)

func (l PathLocation) String() string {
	switch l {
	case Source:
		return "source"
	case Transit:
		return "trantit"
	case Destination:
		return "destination"
	}
	return "unknown path location"
}

// Location returns the location of this node in the path of the request.
func (r *SetupReq) Location() PathLocation {
	switch len(r.AllocationTrail) {
	case 0:
		return Source
	case r.totalASCount:
		return Destination
	default:
		return Transit
	}
}

// SegmentRsvIDsForThisAS returns the segment reservation ID this AS belongs to. Iff this
// AS is a transfer AS (stitching point), there will be two reservation IDs returned, in the
// order of traversal.
func (r *SetupReq) SegmentRsvIDsForThisAS() []reservation.SegmentID {
	indices := make([]reservation.SegmentID, 1, 2)
	indices[0] = r.SegmentRsvs[r.currentASSegmentRsvIndex]
	if r.isTransfer {
		indices = append(indices, r.SegmentRsvs[r.currentASSegmentRsvIndex+1])
	}
	return indices
}

// SetupReqSuccess is a successful e2e setup request traveling along the reservation path.
type SetupReqSuccess struct {
	SetupReq
	Token reservation.Token
}

var _ SetupRequest = (*SetupReqSuccess)(nil)

// IsSuccessful returns true.
func (s *SetupReqSuccess) IsSuccessful() bool {
	return true
}

// SetupReqFailure is a failed e2e setup request also traveling along the reservation path.
type SetupReqFailure struct {
	SetupReq
	ErrorCode uint8
}

var _ SetupRequest = (*SetupReqFailure)(nil)

// IsSuccessful returns false, as this is a failed setup.
func (s *SetupReqFailure) IsSuccessful() bool {
	return false
}

// CleanupReq is a cleaup request for an e2e index.
type CleanupReq struct {
	Request
}
