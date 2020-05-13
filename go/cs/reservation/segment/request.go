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

	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/serrors"
)

// SetupReq is a segment reservation setup request. It contains a reference to the reservation
// it requests, or nil if not yet created.
// This same type is used for renewal of the segment reservation.
type SetupReq struct {
	Reservation *Reservation // nil if no reservation yet
	Timestamp   time.Time
	MinBW       uint8
	MaxBW       uint8
	SplitCls    uint8
	PathProps   reservation.PathEndProps
	AllocTrail  []reservation.AllocationBead
}

func NewRequestFromCtrlMsg(setup *colibri_mgmt.SegmentSetup, timestamp time.Time) *SetupReq {
	s := SetupReq{
		Timestamp:  timestamp,
		MinBW:      setup.MinBW,
		MaxBW:      setup.MaxBW,
		SplitCls:   setup.SplitCls,
		AllocTrail: make([]reservation.AllocationBead, len(setup.AllocationTrail)),
		PathProps: reservation.NewPathEndProps(setup.StartProps.Local, setup.StartProps.Transfer,
			setup.EndProps.Local, setup.EndProps.Transfer),
	}
	for i, ab := range setup.AllocationTrail {
		s.AllocTrail[i] = reservation.AllocationBead{
			AllocBW: ab.AllocBW,
			MaxBW:   ab.MaxBW,
		}
	}
	return &s
}

// ToCtrlMsg creates a new segment setup control message filled with the information from here.
func (r *SetupReq) ToCtrlMsg() *colibri_mgmt.SegmentSetup {
	msg := &colibri_mgmt.SegmentSetup{
		MinBW:    r.MinBW,
		MaxBW:    r.MaxBW,
		SplitCls: r.SplitCls,
		StartProps: colibri_mgmt.PathEndProps{
			Local:    (r.PathProps & reservation.StartLocal) != 0,
			Transfer: (r.PathProps & reservation.StartTransfer) != 0,
		},
		EndProps: colibri_mgmt.PathEndProps{
			Local:    (r.PathProps & reservation.EndLocal) != 0,
			Transfer: (r.PathProps & reservation.EndTransfer) != 0,
		},
		AllocationTrail: make([]*colibri_mgmt.AllocationBeads, len(r.AllocTrail)),
	}
	for i, bead := range r.AllocTrail {
		msg.AllocationTrail[i] = &colibri_mgmt.AllocationBeads{
			AllocBW: bead.AllocBW,
			MaxBW:   bead.MaxBW,
		}
	}
	return msg
}

// SetupTelesReq represents a telescopic segment setup.
type SetupTelesReq struct {
	SetupReq
	BaseID reservation.SegmentID
}

func NewTelesRequestFromCtrlMsg(setup *colibri_mgmt.SegmentTelesSetup, timestamp time.Time) (
	*SetupTelesReq, error) {

	if setup.BaseID == nil || setup.Setup == nil {
		return nil, serrors.New("illegal ctrl telescopic setup received", "base_id", setup.BaseID,
			"segment_setup", setup.Setup)
	}
	s := SetupTelesReq{
		SetupReq: *NewRequestFromCtrlMsg(setup.Setup, timestamp),
	}
	id, err := reservation.SegmentIDFromRawBuffers(setup.BaseID.ASID, setup.BaseID.Suffix)
	if err != nil {
		return nil, err
	}
	s.BaseID = *id
	return &s, nil
}

// ToCtrlMsg creates a new segment telescopic setup control message from this request.
func (r *SetupTelesReq) ToCtrlMsg() *colibri_mgmt.SegmentTelesSetup {
	buff := make([]byte, reservation.SegmentIDLen)
	r.BaseID.Read(buff)
	return &colibri_mgmt.SegmentTelesSetup{
		Setup: r.SetupReq.ToCtrlMsg(),
		BaseID: &colibri_mgmt.SegmentReservationID{
			ASID:   buff[:6],
			Suffix: buff[6:],
		},
	}
}
