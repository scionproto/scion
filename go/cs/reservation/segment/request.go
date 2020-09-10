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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
)

// Request is the base struct for any type of COLIBRI segment request.
// It contains a reference to the reservation it requests, or nil if not yet created.
type Request struct {
	base.RequestMetadata                         // information about the request (forwarding path)
	ID                   reservation.SegmentID   // the ID this request refers to
	Index                reservation.IndexNumber // the index this request refers to
	Timestamp            time.Time               // the mandatory timestamp
	Ingress              common.IFIDType         // the interface the traffic uses to enter the AS
	Egress               common.IFIDType         // the interface the traffic uses to leave the AS
	Reservation          *Reservation            // nil if no reservation yet
}

// NewRequest constructs the segment Request type.
func NewRequest(ts time.Time, id *reservation.SegmentID, idx reservation.IndexNumber,
	path *spath.Path) (*Request, error) {

	metadata, err := base.NewRequestMetadata(path)
	if err != nil {
		return nil, serrors.WrapStr("new segment request", err)
	}
	hf, err := path.GetHopField(path.HopOff)
	if err != nil {
		return nil, serrors.WrapStr("cannot get ingress and egress IFIDs from the setup request",
			err, "hop_off", path.HopOff)
	}
	ingressIFID, egressIFID := hf.ConsIngress, hf.ConsEgress
	infField, err := path.GetInfoField(path.InfOff)
	if err != nil {
		return nil, serrors.WrapStr("cannot obtain infofield from spath", err)
	}
	if !infField.ConsDir {
		egressIFID, ingressIFID = ingressIFID, egressIFID
	}
	if id == nil {
		return nil, serrors.New("new segment request with nil ID")
	}
	return &Request{
		RequestMetadata: *metadata,
		Timestamp:       ts,
		ID:              *id,
		Index:           idx,
		Ingress:         ingressIFID,
		Egress:          egressIFID,
	}, nil
}

// SetupReq is a segment reservation setup request.
// This same type is used for renewal of the segment reservation.
type SetupReq struct {
	Request
	InfoField  reservation.InfoField
	MinBW      reservation.BWCls
	MaxBW      reservation.BWCls
	SplitCls   reservation.SplitCls
	PathProps  reservation.PathEndProps
	AllocTrail reservation.AllocationBeads
}

// SetupTelesReq represents a telescopic segment setup.
type SetupTelesReq struct {
	SetupReq
	BaseID reservation.SegmentID
}

// TeardownReq requests the AS to remove a given index from the DB. If this is the last index
// in the reservation, the reservation will be completely removed.
type TeardownReq struct {
	Request
}

// IndexConfirmationReq is used to change the state on an index (e.g. from temporary to pending).
type IndexConfirmationReq struct {
	Request
	State IndexState
}

// CleanupReq is used to clean an index.
type CleanupReq struct {
	Request
}
