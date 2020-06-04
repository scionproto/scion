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

	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/serrors"
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
	reservation *Reservation
	ID          reservation.E2EID
	timestamp   time.Time
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
func NewRequestFromCtrlMsg(setup *colibri_mgmt.E2ESetup, ts time.Time) (SetupReq, error) {
	var s SetupReq
	id, err := reservation.E2EIDFromRawBuffers(setup.ReservationID.ASID, setup.ReservationID.Suffix)
	if err != nil {
		return nil, err
	}
	switch {
	case setup.Success != nil:
		tok, err := reservation.TokenFromRaw(setup.Success.Token)
		if err != nil {
			return nil, err
		}
		s = &SuccessSetupReq{
			BaseSetupReq: BaseSetupReq{timestamp: ts, ID: *id},
			Token:        *tok,
		}
	case setup.Failure != nil:
		ifield, err := reservation.InfoFieldFromRaw(setup.Failure.InfoField)
		if err != nil {
			return nil, err
		}
		bwTrail := make([]reservation.BWCls, len(setup.Failure.MaxBWs))
		for i, bw := range setup.Failure.MaxBWs {
			bwTrail[i] = reservation.BWCls(bw)
		}
		s = &FailureSetupReq{
			BaseSetupReq: BaseSetupReq{timestamp: ts, ID: *id},
			ErrorCode:    int(setup.Failure.ErrorCode),
			InfoField:    *ifield,
			MaxBWTrail:   bwTrail,
		}
	default:
		return nil, serrors.New("invalid E2E setup request received, neither successful or failed",
			"success_ptr", setup.Success, "failure_ptr", setup.Failure)
	}
	return s, nil
}
