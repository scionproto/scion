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

package e2e_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/reservation/e2e"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

func TestNewRequestFromCtrlMsg(t *testing.T) {
	setup := newE2ESetupSuccess()
	ts := time.Unix(1, 0)
	_, err := e2e.NewRequestFromCtrlMsg(setup, ts, nil)
	require.Error(t, err) // no path
	p := newPath()
	r, err := e2e.NewRequestFromCtrlMsg(setup, ts, p)
	require.NoError(t, err)
	checkRequest(t, setup, r, ts, p)

	setup = newE2ESetupFailure()
	_, err = e2e.NewRequestFromCtrlMsg(setup, ts, nil)
	require.Error(t, err) // no path
	r, err = e2e.NewRequestFromCtrlMsg(setup, ts, p)
	require.NoError(t, err)
	checkRequest(t, setup, r, ts, p)
}

func TestRequestToCtrlMsg(t *testing.T) {
	setup := newE2ESetupSuccess()
	ts := time.Unix(1, 0)
	r, _ := e2e.NewRequestFromCtrlMsg(setup, ts, newPath())
	anotherSetup, err := r.ToCtrlMsg()
	require.NoError(t, err)
	require.Equal(t, setup, anotherSetup)

	setup = newE2ESetupFailure()
	r, _ = e2e.NewRequestFromCtrlMsg(setup, ts, newPath())
	anotherSetup, err = r.ToCtrlMsg()
	require.NoError(t, err)
	require.Equal(t, setup, anotherSetup)
}

func newE2ESetupSuccess() *colibri_mgmt.E2ESetup {
	return &colibri_mgmt.E2ESetup{
		ReservationID: &colibri_mgmt.E2EReservationID{
			ASID:   xtest.MustParseHexString("ff00cafe0001"),
			Suffix: xtest.MustParseHexString("0123456789abcdef0123"),
		},
		Which: proto.E2ESetupData_Which_success,
		Success: &colibri_mgmt.E2ESetupSuccess{
			Token: xtest.MustParseHexString("16ebdb4f0d042500003f001002bad1ce003f001002facade"),
		},
	}
}

func newE2ESetupFailure() *colibri_mgmt.E2ESetup {
	return &colibri_mgmt.E2ESetup{
		ReservationID: &colibri_mgmt.E2EReservationID{
			ASID:   xtest.MustParseHexString("ff00cafe0001"),
			Suffix: xtest.MustParseHexString("0123456789abcdef0123"),
		},
		Which: proto.E2ESetupData_Which_failure,
		Failure: &colibri_mgmt.E2ESetupFailure{
			ErrorCode: 42,
			InfoField: xtest.MustParseHexString("16ebdb4f0d042500"),
			MaxBWs:    []uint8{1, 2},
		},
	}
}

// new path with one segment consisting on 3 hopfields: (0,2)->(1,2)->(1,0)
func newPath() *spath.Path {
	path := &spath.Path{
		InfOff: 0,
		HopOff: spath.InfoFieldLength + spath.HopFieldLength, // second hop field
		Raw:    make([]byte, spath.InfoFieldLength+3*spath.HopFieldLength),
	}
	inf := spath.InfoField{ConsDir: true, ISD: 1, Hops: 3}
	inf.Write(path.Raw)

	hf := &spath.HopField{ConsEgress: 2}
	hf.Write(path.Raw[spath.InfoFieldLength:])
	hf = &spath.HopField{ConsIngress: 1, ConsEgress: 2}
	hf.Write(path.Raw[spath.InfoFieldLength+spath.HopFieldLength:])
	hf = &spath.HopField{ConsIngress: 1}
	hf.Write(path.Raw[spath.InfoFieldLength+spath.HopFieldLength*2:])

	return path
}

func checkRequest(t *testing.T, e2eSetup *colibri_mgmt.E2ESetup, r e2e.SetupReq, ts time.Time,
	p *spath.Path) {
	var base *e2e.BaseSetupReq
	var successSetup *e2e.SuccessSetupReq
	var failureSetup *e2e.FailureSetupReq
	switch s := r.(type) {
	case *e2e.SuccessSetupReq:
		base = &s.BaseSetupReq
		successSetup = s
	case *e2e.FailureSetupReq:
		base = &s.BaseSetupReq
		failureSetup = s
	default:
		require.FailNow(t, "invalid type for request", "request type: %T", r)
	}

	require.Equal(t, (*e2e.Reservation)(nil), base.Reservation())
	require.Equal(t, ts, base.Timestamp())
	require.Equal(t, *p, base.Path)
	buff := make([]byte, reservation.E2EIDLen)
	_, err := base.ID.Read(buff)
	require.NoError(t, err) // tested in the E2EID UT, should not fail
	require.Equal(t, e2eSetup.ReservationID.ASID, buff[:6])
	require.Equal(t, e2eSetup.ReservationID.Suffix, buff[6:])

	if successSetup != nil {
		buff := make([]byte, len(e2eSetup.Success.Token))
		_, err := successSetup.Token.Read(buff)
		require.NoError(t, err) // tested in the Token UT, should not fail
		require.Equal(t, e2eSetup.Success.Token, buff)
	}
	if failureSetup != nil {
		require.Equal(t, int(e2eSetup.Failure.ErrorCode), failureSetup.ErrorCode)
		buff := make([]byte, reservation.InfoFieldLen)
		_, err := failureSetup.InfoField.Read(buff)
		require.NoError(t, err) // tested in the InfoField UT, should not fail
		require.Equal(t, e2eSetup.Failure.InfoField, buff)
		trail := make([]uint8, len(failureSetup.MaxBWTrail))
		for i := range trail {
			trail[i] = uint8(failureSetup.MaxBWTrail[i])
		}
		require.Equal(t, e2eSetup.Failure.MaxBWs, trail)

	}
}
