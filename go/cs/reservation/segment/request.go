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
	"encoding/hex"
	"time"

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
)

// Request is the base struct for any type of COLIBRI request.
type Request struct {
	base.RequestMetadata                       // information about the request (forwarding path)
	ID                   reservation.SegmentID // the ID this request refers to
	Timestamp            time.Time             // the mandatory timestamp
	Ingress              common.IFIDType       // the interface the reservation traffic uses to enter the AS
	Egress               common.IFIDType       // the interface the reservation traffic uses to leave the AS
	Reservation          *Reservation          // nil if no reservation yet
}

// NewRequest constructs the segment Request type.
func NewRequest(ts time.Time, ID *colibri_mgmt.SegmentReservationID,
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
	if ID == nil {
		return nil, serrors.New("new segment request with nil ID")
	}
	segID, err := reservation.SegmentIDFromRawBuffers(ID.ASID, ID.Suffix)
	if err != nil {
		return nil, serrors.WrapStr("new segment request", err)
	}
	return &Request{
		RequestMetadata: *metadata,
		Timestamp:       ts,
		ID:              *segID,
		Ingress:         ingressIFID,
		Egress:          egressIFID,
	}, nil
}

// SetupReq is a segment reservation setup request. It contains a reference to the reservation
// it requests, or nil if not yet created.
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

// NewSetupReqFromCtrlMsg constructs a SetupReq from its control message counterpart. The timestamp
// comes from the wrapping ColibriRequestPayload, and the spath from the wrapping SCION packet.
func NewSetupReqFromCtrlMsg(setup *colibri_mgmt.SegmentSetup, ts time.Time,
	ID *colibri_mgmt.SegmentReservationID, path *spath.Path) (*SetupReq, error) {

	r, err := NewRequest(ts, ID, path)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct segment setup request", err)
	}
	inF, err := reservation.InfoFieldFromRaw(setup.InfoField)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct info field from raw", err)
	}
	if inF == nil {
		return nil, serrors.New("empty info field", "raw", hex.EncodeToString(setup.InfoField))
	}
	s := SetupReq{
		Request:    *r,
		InfoField:  *inF,
		MinBW:      reservation.BWCls(setup.MinBW),
		MaxBW:      reservation.BWCls(setup.MaxBW),
		SplitCls:   reservation.SplitCls(setup.SplitCls),
		AllocTrail: make(reservation.AllocationBeads, len(setup.AllocationTrail)),
		PathProps: reservation.NewPathEndProps(setup.StartProps.Local, setup.StartProps.Transfer,
			setup.EndProps.Local, setup.EndProps.Transfer),
	}
	for i, ab := range setup.AllocationTrail {
		s.AllocTrail[i] = reservation.AllocationBead{
			AllocBW: reservation.BWCls(ab.AllocBW),
			MaxBW:   reservation.BWCls(ab.MaxBW),
		}
	}
	return &s, nil
}

// ToCtrlMsg creates a new segment setup control message filled with the information from here.
func (r *SetupReq) ToCtrlMsg() *colibri_mgmt.SegmentSetup {

	msg := &colibri_mgmt.SegmentSetup{
		MinBW:    uint8(r.MinBW),
		MaxBW:    uint8(r.MaxBW),
		SplitCls: uint8(r.SplitCls),
		StartProps: colibri_mgmt.PathEndProps{
			Local:    (r.PathProps & reservation.StartLocal) != 0,
			Transfer: (r.PathProps & reservation.StartTransfer) != 0,
		},
		EndProps: colibri_mgmt.PathEndProps{
			Local:    (r.PathProps & reservation.EndLocal) != 0,
			Transfer: (r.PathProps & reservation.EndTransfer) != 0,
		},
		InfoField:       r.InfoField.ToRaw(),
		AllocationTrail: make([]*colibri_mgmt.AllocationBead, len(r.AllocTrail)),
	}
	for i, bead := range r.AllocTrail {
		msg.AllocationTrail[i] = &colibri_mgmt.AllocationBead{
			AllocBW: uint8(bead.AllocBW),
			MaxBW:   uint8(bead.MaxBW),
		}
	}
	return msg
}

// SetupTelesReq represents a telescopic segment setup.
type SetupTelesReq struct {
	SetupReq
	BaseID reservation.SegmentID
}

// NewTelesRequestFromCtrlMsg constucts the app type from its control message counterpart.
func NewTelesRequestFromCtrlMsg(setup *colibri_mgmt.SegmentTelesSetup, ts time.Time,
	ID *colibri_mgmt.SegmentReservationID, path *spath.Path) (*SetupTelesReq, error) {

	if setup.BaseID == nil || setup.Setup == nil {
		return nil, serrors.New("illegal ctrl telescopic setup received", "base_id", setup.BaseID,
			"segment_setup", setup.Setup)
	}
	baseReq, err := NewSetupReqFromCtrlMsg(setup.Setup, ts, ID, path)
	if err != nil {
		return nil, serrors.WrapStr("failed to construct base request", err)
	}
	s := SetupTelesReq{
		SetupReq: *baseReq,
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

// IndexConfirmationReq is used to change the state on an index (e.g. from temporary to pending).
type IndexConfirmationReq struct {
	Request
	IndexNumber reservation.IndexNumber
	State       IndexState
}

// NewIndexConfirmationReqFromCtrlMsg constructs the application type from its control counterpart.
func NewIndexConfirmationReqFromCtrlMsg(ctrl *colibri_mgmt.SegmentIndexConfirmation, ts time.Time,
	ID *colibri_mgmt.SegmentReservationID, path *spath.Path) (*IndexConfirmationReq, error) {

	r, err := NewRequest(ts, ID, path)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct index confirmation request", err)
	}
	st, err := NewIndexStateFromCtrlMsg(ctrl.State)
	if err != nil {
		return nil, err
	}
	return &IndexConfirmationReq{
		Request:     *r,
		IndexNumber: reservation.IndexNumber(ctrl.Index),
		State:       st,
	}, nil
}

// ToCtrlMsg converts this application type to its control message counterpart.
func (r *IndexConfirmationReq) ToCtrlMsg() (*colibri_mgmt.SegmentIndexConfirmation, error) {
	st, err := r.State.ToCtrlMsg()
	if err != nil {
		return nil, err
	}
	return &colibri_mgmt.SegmentIndexConfirmation{
		Index: uint8(r.IndexNumber),
		State: st,
	}, nil
}

// CleanupReq is used to clean an index.
type CleanupReq struct {
	Request
	IndexNumber reservation.IndexNumber
}

// NewCleanupReqFromCtrlMsg contructs a cleanup request from its control message counterpart.
func NewCleanupReqFromCtrlMsg(ctrl *colibri_mgmt.SegmentCleanup, ts time.Time,
	path *spath.Path) (*CleanupReq, error) {

	// we use the ID inside the control message, as the request could have come without COLIBRI
	r, err := NewRequest(ts, ctrl.ID, path)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct index cleanup request", err)
	}
	return &CleanupReq{
		Request:     *r,
		IndexNumber: reservation.IndexNumber(ctrl.Index),
	}, nil
}

// ToCtrlMsg converts this application type to its control message counterpart.
func (r *CleanupReq) ToCtrlMsg() *colibri_mgmt.SegmentCleanup {
	rawid := make([]byte, reservation.SegmentIDLen)
	r.ID.Read(rawid)
	return &colibri_mgmt.SegmentCleanup{
		ID: &colibri_mgmt.SegmentReservationID{
			ASID:   rawid[:6],
			Suffix: rawid[6:],
		},
		Index: uint8(r.IndexNumber),
	}
}
