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
	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/proto"
)

// SetupReq is the interface for an e2e setup request.
// Currently it's implemented by either SuccessSetupReq or FailureSetupReq.
type SetupReq interface {
	Reservation() *Reservation
	Timestamp() time.Time
	ToCtrlMsg() (*colibri_mgmt.E2ESetup, error)
}

// BaseSetupReq is the common part of any e2e setup request.
type BaseSetupReq struct {
	base.RequestMetadata                   // information about the request (forwarding path)
	ID                   reservation.E2EID // the ID this request refers to
	timestamp            time.Time         // the mandatory timestamp
	reservation          *Reservation      // nil if no reservation yet
}

func NewBaseSetupReq(path *spath.Path, ts time.Time,
	ID *colibri_mgmt.E2EReservationID) (*BaseSetupReq, error) {

	metadata, err := base.NewRequestMetadata(path)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct e2e setup", err)
	}
	if ID == nil {
		return nil, serrors.New("new e2e request with nil ID")
	}
	e2eID, err := reservation.E2EIDFromRawBuffers(ID.ASID, ID.Suffix)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct e2e request", err)
	}
	return &BaseSetupReq{
		RequestMetadata: *metadata,
		ID:              *e2eID,
		timestamp:       ts,
	}, nil
}

func (r *BaseSetupReq) Timestamp() time.Time      { return r.timestamp }
func (r *BaseSetupReq) Reservation() *Reservation { return r.reservation }

func (r *BaseSetupReq) ToCtrlMsg() (*colibri_mgmt.E2ESetup, error) {
	id := make([]byte, reservation.E2EIDLen)
	_, err := r.ID.Read(id)
	if err != nil {
		return nil, err
	}
	return &colibri_mgmt.E2ESetup{
		ReservationID: &colibri_mgmt.E2EReservationID{
			ASID:   id[:6],
			Suffix: id[6:],
		},
	}, nil
}

// SuccessSetupReq is a successful e2e resevation setup request.
type SuccessSetupReq struct {
	BaseSetupReq
	Token reservation.Token
}

var _ SetupReq = (*SuccessSetupReq)(nil)

// NewSuccessSetupReq constructs the app type from its control message.
func NewSuccessSetupReq(path *spath.Path, ts time.Time, ID *colibri_mgmt.E2EReservationID,
	ctrl *colibri_mgmt.E2ESetupSuccess) (*SuccessSetupReq, error) {

	baseReq, err := NewBaseSetupReq(path, ts, ID)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct success e2e setup", err)
	}
	tok, err := reservation.TokenFromRaw(ctrl.Token)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct success e2e setup", err)
	}
	return &SuccessSetupReq{
		BaseSetupReq: *baseReq,
		Token:        *tok,
	}, nil
}

func (r *SuccessSetupReq) ToCtrlMsg() (*colibri_mgmt.E2ESetup, error) {
	ctrl, err := r.BaseSetupReq.ToCtrlMsg()
	if err != nil {
		return nil, err
	}
	token := make([]byte, r.Token.Len())
	_, err = r.Token.Read(token)
	if err != nil {
		return nil, err
	}
	ctrl.Which = proto.E2ESetupData_Which_success
	ctrl.Success = &colibri_mgmt.E2ESetupSuccess{
		Token: token,
	}
	return ctrl, nil
}

// FailureSetupReq is a failing e2e resevation setup request.
type FailureSetupReq struct {
	BaseSetupReq
	ErrorCode  int
	InfoField  reservation.InfoField
	MaxBWTrail []reservation.BWCls
}

var _ SetupReq = (*FailureSetupReq)(nil)

func NewFailureSetupReq(path *spath.Path, ts time.Time, ID *colibri_mgmt.E2EReservationID,
	ctrl *colibri_mgmt.E2ESetupFailure) (*FailureSetupReq, error) {

	baseReq, err := NewBaseSetupReq(path, ts, ID)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct failure e2e setup", err)
	}
	ifield, err := reservation.InfoFieldFromRaw(ctrl.InfoField)
	if err != nil {
		return nil, err
	}
	bwTrail := make([]reservation.BWCls, len(ctrl.MaxBWs))
	for i, bw := range ctrl.MaxBWs {
		bwTrail[i] = reservation.BWCls(bw)
	}
	return &FailureSetupReq{
		BaseSetupReq: *baseReq,
		ErrorCode:    int(ctrl.ErrorCode),
		InfoField:    *ifield,
		MaxBWTrail:   bwTrail,
	}, nil
}

func (r *FailureSetupReq) ToCtrlMsg() (*colibri_mgmt.E2ESetup, error) {
	ctrl, err := r.BaseSetupReq.ToCtrlMsg()
	if err != nil {
		return nil, err
	}
	inf := make([]byte, reservation.InfoFieldLen)
	_, err = r.InfoField.Read(inf)
	if err != nil {
		return nil, err
	}
	trail := make([]uint8, len(r.MaxBWTrail))
	for i, bw := range r.MaxBWTrail {
		trail[i] = uint8(bw)
	}
	ctrl.Which = proto.E2ESetupData_Which_failure
	ctrl.Failure = &colibri_mgmt.E2ESetupFailure{
		ErrorCode: uint8(r.ErrorCode),
		InfoField: inf,
		MaxBWs:    trail,
	}
	return ctrl, nil
}

// NewRequestFromCtrlMsg will return a SuccessSetupReq or FailSetupReq depending on the
// success flag of the ctrl message.
func NewRequestFromCtrlMsg(setup *colibri_mgmt.E2ESetup, ts time.Time,
	path *spath.Path) (SetupReq, error) {

	var s SetupReq
	var err error
	switch {
	case setup.Success != nil:
		s, err = NewSuccessSetupReq(path, ts, setup.ReservationID, setup.Success)
	case setup.Failure != nil:
		s, err = NewFailureSetupReq(path, ts, setup.ReservationID, setup.Failure)
	default:
		return nil, serrors.New("invalid E2E setup request received, neither successful or failed",
			"success_ptr", setup.Success, "failure_ptr", setup.Failure)
	}
	return s, err
}

// CleanupReq is a cleaup request for an e2e index.
type CleanupReq struct {
	BaseSetupReq
}

// NewCleanupReqFromCtrlMsg contructs a cleanup request from its control message counterpart.
func NewCleanupReqFromCtrlMsg(ctrl *colibri_mgmt.E2ECleanup, ts time.Time,
	path *spath.Path) (*CleanupReq, error) {

	baseReq, err := NewBaseSetupReq(path, ts, ctrl.ReservationID)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct cleanup request", err)
	}
	return &CleanupReq{
		BaseSetupReq: *baseReq,
	}, nil
}

// ToCtrlMsg converts this application type to its control message counterpart.
func (r *CleanupReq) ToCtrlMsg() *colibri_mgmt.E2ECleanup {
	rawid := make([]byte, reservation.E2EIDLen)
	r.ID.Read(rawid)
	return &colibri_mgmt.E2ECleanup{
		ReservationID: &colibri_mgmt.E2EReservationID{
			ASID:   rawid[:6],
			Suffix: rawid[6:],
		},
	}
}
