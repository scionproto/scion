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

package translate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/reservation/e2e"
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/cs/reservation/test"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

func TestNewSegmentIDFromCtrl(t *testing.T) {
	ctrl := newTestID()
	id, err := NewSegmentIDFromCtrl(ctrl)
	require.NoError(t, err)
	rawid := id.ToRaw()
	require.Equal(t, ctrl.ASID, rawid[:6])
	require.Equal(t, ctrl.Suffix, rawid[6:])
}

func TestNewE2EIDFromCtrl(t *testing.T) {
	ctrl := newTestE2EID()
	id, err := NewE2EIDFromCtrl(ctrl)
	require.NoError(t, err)
	rawid := id.ToRaw()
	require.Equal(t, ctrl.ASID, rawid[:6])
	require.Equal(t, ctrl.Suffix, rawid[6:])
}

func TestNewRequestSegmentSetupFromCtrl(t *testing.T) {
	ctrlMsg := newTestSetup()
	ts := util.SecsToTime(1)
	r, err := newRequestSegmentSetup(ctrlMsg, ts, nil)
	require.Error(t, err) // missing path
	p := test.NewTestPath()
	r, err = newRequestSegmentSetup(ctrlMsg, ts, p)
	require.NoError(t, err)
	require.Equal(t, p, r.Path())
	checkRequest(t, ctrlMsg, r, ts)
	require.EqualValues(t, 1, r.Ingress)
	require.EqualValues(t, 2, r.Egress)
}

func TestNewRequestSegmentTelesSetup(t *testing.T) {
	ctrlMsg := newTestTelesSetup()
	ts := util.SecsToTime(1)
	r, err := newRequestSegmentTelesSetup(ctrlMsg, ts, nil)
	require.Error(t, err) // path is nil
	r, err = newRequestSegmentTelesSetup(ctrlMsg, ts, test.NewTestPath())
	require.NoError(t, err)
	checkRequest(t, ctrlMsg.Setup, &r.SetupReq, ts)
	require.Equal(t, xtest.MustParseAS("ff00:cafe:1"), r.BaseID.ASID)
	require.Equal(t, xtest.MustParseHexString("deadbeef"), r.BaseID.Suffix[:])
}

func TestNewRequestSegmentTeardown(t *testing.T) {
	ctrlMsg := newTestSegmentTeardown()
	ts := util.SecsToTime(1)
	r, err := newRequestSegmentTeardown(ctrlMsg, ts, nil)
	require.Error(t, err) // path is nil
	r, err = newRequestSegmentTeardown(ctrlMsg, ts, test.NewTestPath())
	require.NoError(t, err)
	checkIDs(t, ctrlMsg.Base.ID, &r.ID)
	require.Equal(t, ctrlMsg.Base.Index, uint8(r.Index))
}

func TestNewRequestSegmentIndexConfirmation(t *testing.T) {
	ctrlMsg := newTestIndexConfirmation()
	ts := util.SecsToTime(1)
	r, err := newRequestSegmentIndexConfirmation(ctrlMsg, ts, nil)
	require.Error(t, err) // nil path
	r, err = newRequestSegmentIndexConfirmation(ctrlMsg, ts, test.NewTestPath())
	require.NoError(t, err)
	checkIDs(t, ctrlMsg.Base.ID, &r.ID)
	require.Equal(t, ctrlMsg.Base.Index, uint8(r.Index))
	require.Equal(t, segment.IndexActive, r.State)
}

func TestNewRequestSegmentCleanup(t *testing.T) {
	ctrlMsg := newTestCleanup()
	ts := util.SecsToTime(1)
	r, err := newRequestSegmentCleanup(ctrlMsg, ts, nil)
	require.Error(t, err) // nil path
	r, err = newRequestSegmentCleanup(ctrlMsg, ts, test.NewTestPath())
	require.NoError(t, err)
	checkIDs(t, ctrlMsg.Base.ID, &r.ID)
	require.Equal(t, ctrlMsg.Base.Index, uint8(r.Index))
}

func TestNewRequestE2ESetupSuccess(t *testing.T) {
	ctrlMsg := newTestE2ESetupSuccess()
	ts := util.SecsToTime(1)
	_, err := newRequestE2ESetup(ctrlMsg, ts, nil)
	require.Error(t, err)
	s, err := newRequestE2ESetup(ctrlMsg, ts, test.NewTestPath())
	require.NoError(t, err)
	require.IsType(t, &e2e.SetupReqSuccess{}, s)
	r := s.(*e2e.SetupReqSuccess)
	checkE2EIDs(t, ctrlMsg.Base.ID, &r.ID)
	require.Equal(t, ctrlMsg.Base.Index, uint8(r.Index))
	segmentRsvs := make([]reservation.SegmentID, len(ctrlMsg.SegmentRsvs))
	for i := range ctrlMsg.SegmentRsvs {
		id, err := reservation.SegmentIDFromRawBuffers(ctrlMsg.SegmentRsvs[i].ASID,
			ctrlMsg.SegmentRsvs[i].Suffix)
		require.NoError(t, err)
		segmentRsvs[i] = *id
	}
	require.Equal(t, segmentRsvs, r.SegmentRsvs)
	require.Equal(t, ctrlMsg.RequestedBW, uint8(r.RequestedBW))
	allocTrail := make([]reservation.BWCls, len(ctrlMsg.AllocationTrail))
	for i := range ctrlMsg.AllocationTrail {
		allocTrail[i] = reservation.BWCls(ctrlMsg.AllocationTrail[i])
	}
	require.Equal(t, allocTrail, r.AllocationTrail)
	require.Equal(t, ctrlMsg.Success.Token, r.Token.ToRaw())
}

func TestNewRequestE2ESetupFailure(t *testing.T) {
	ctrlMsg := newTestE2ESetupFailure()
	ts := util.SecsToTime(1)
	_, err := newRequestE2ESetup(ctrlMsg, ts, nil)
	require.Error(t, err)
	s, err := newRequestE2ESetup(ctrlMsg, ts, test.NewTestPath())
	require.NoError(t, err)
	require.IsType(t, &e2e.SetupReqFailure{}, s)
	r := s.(*e2e.SetupReqFailure)
	checkE2EIDs(t, ctrlMsg.Base.ID, &r.ID)
	require.Equal(t, ctrlMsg.Base.Index, uint8(r.Index))
	segmentRsvs := make([]reservation.SegmentID, len(ctrlMsg.SegmentRsvs))
	for i := range ctrlMsg.SegmentRsvs {
		id, err := reservation.SegmentIDFromRawBuffers(ctrlMsg.SegmentRsvs[i].ASID,
			ctrlMsg.SegmentRsvs[i].Suffix)
		require.NoError(t, err)
		segmentRsvs[i] = *id
	}
	require.Equal(t, segmentRsvs, r.SegmentRsvs)
	require.Equal(t, ctrlMsg.RequestedBW, uint8(r.RequestedBW))
	allocTrail := make([]reservation.BWCls, len(ctrlMsg.AllocationTrail))
	for i := range ctrlMsg.AllocationTrail {
		allocTrail[i] = reservation.BWCls(ctrlMsg.AllocationTrail[i])
	}
	require.Equal(t, allocTrail, r.AllocationTrail)
	require.Equal(t, ctrlMsg.Failure.ErrorCode, r.ErrorCode)
}

func TestNewRequestE2ECleanup(t *testing.T) {
	ctrlMsg := newTestE2ECleanup()
	ts := util.SecsToTime(1)
	r, err := newRequestE2ECleanup(ctrlMsg, ts, nil)
	require.Error(t, err)
	r, err = newRequestE2ECleanup(ctrlMsg, ts, test.NewTestPath())
	require.NoError(t, err)
	checkE2EIDs(t, ctrlMsg.Base.ID, &r.ID)
	require.Equal(t, ctrlMsg.Base.Index, uint8(r.Index))
}

func TestNewResponseSegmentSetup(t *testing.T) {
	cases := map[string]struct {
		Ctrl *colibri_mgmt.Response
	}{
		"success": {
			Ctrl: &colibri_mgmt.Response{
				SegmentSetup: newTestSegmentSetupSuccessResponse(),
				Which:        proto.Response_Which_segmentSetup,
				Accepted:     true,
			},
		},
		"failure": {
			Ctrl: &colibri_mgmt.Response{
				SegmentSetup: newTestSegmentSetupFailureResponse(),
				Which:        proto.Response_Which_segmentSetup,
				Accepted:     false,
				FailedHop:    9,
			},
		},
	}

	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ts := util.SecsToTime(1)
			_, err := newResponseSegmentSetup(tc.Ctrl.SegmentSetup, tc.Ctrl, ts, nil)
			require.Error(t, err)
			r, err := newResponseSegmentSetup(tc.Ctrl.SegmentSetup, tc.Ctrl, ts,
				test.NewTestPath())
			require.NoError(t, err)
			require.NotNil(t, r)
			if tc.Ctrl.Accepted {
				require.IsType(t, &segment.ResponseSetupSuccess{}, r)
				rs := r.(*segment.ResponseSetupSuccess)
				checkIDs(t, tc.Ctrl.SegmentSetup.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.SegmentSetup.Base.Index, uint8(rs.Index))
				require.Equal(t, tc.Ctrl.SegmentSetup.Token, rs.Token.ToRaw())
			} else {
				require.IsType(t, &segment.ResponseSetupFailure{}, r)
				rs := r.(*segment.ResponseSetupFailure)
				checkIDs(t, tc.Ctrl.SegmentSetup.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.SegmentSetup.Base.Index, uint8(rs.Index))
				checkRequest(t, tc.Ctrl.SegmentSetup.Failure, rs.FailedSetup, ts)
			}
		})
	}
}

func TestNewResponseSegmentTeardown(t *testing.T) {
	cases := map[string]struct {
		Ctrl *colibri_mgmt.Response
	}{
		"success": {
			Ctrl: &colibri_mgmt.Response{
				SegmentTeardown: newTestSegmentTeardownSuccessResponse(),
				Which:           proto.Response_Which_segmentTeardown,
				Accepted:        true,
			},
		},
		"failure": {
			Ctrl: &colibri_mgmt.Response{
				SegmentTeardown: newTestSegmentTeardownFailureResponse(),
				Which:           proto.Response_Which_segmentTeardown,
				Accepted:        false,
				FailedHop:       9,
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ts := util.SecsToTime(1)
			_, err := newResponseSegmentTeardown(tc.Ctrl.SegmentTeardown, tc.Ctrl, ts, nil)
			require.Error(t, err) // no path
			r, err := newResponseSegmentTeardown(tc.Ctrl.SegmentTeardown, tc.Ctrl, ts,
				test.NewTestPath())
			require.NoError(t, err)
			require.NotNil(t, r)
			if tc.Ctrl.Accepted {
				require.IsType(t, &segment.ResponseTeardownSuccess{}, r)
				rs := r.(*segment.ResponseTeardownSuccess)
				checkIDs(t, tc.Ctrl.SegmentTeardown.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.SegmentTeardown.Base.Index, uint8(rs.Index))
			} else {
				require.IsType(t, &segment.ResponseTeardownFailure{}, r)
				rs := r.(*segment.ResponseTeardownFailure)
				checkIDs(t, tc.Ctrl.SegmentTeardown.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.SegmentTeardown.Base.Index, uint8(rs.Index))
				require.Equal(t, tc.Ctrl.SegmentTeardown.ErrorCode, rs.ErrorCode)
			}
		})
	}
}

func TestNewResponseSegmentIndexConfirmation(t *testing.T) {
	cases := map[string]struct {
		Ctrl *colibri_mgmt.Response
	}{
		"success": {
			Ctrl: &colibri_mgmt.Response{
				SegmentIndexConfirmation: newTestIndexConfirmationSuccessResponse(),
				Which:                    proto.Response_Which_segmentIndexConfirmation,
				Accepted:                 true,
			},
		},
		"failure": {
			Ctrl: &colibri_mgmt.Response{
				SegmentIndexConfirmation: newTestIndexConfirmationFailureResponse(),
				Which:                    proto.Response_Which_segmentIndexConfirmation,
				Accepted:                 false,
				FailedHop:                9,
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ts := util.SecsToTime(1)
			_, err := newResponseSegmentIndexConfirmation(tc.Ctrl.SegmentIndexConfirmation,
				tc.Ctrl, ts, nil)
			require.Error(t, err) // no path
			r, err := newResponseSegmentIndexConfirmation(tc.Ctrl.SegmentIndexConfirmation,
				tc.Ctrl, ts, test.NewTestPath())
			require.NoError(t, err)
			require.NotNil(t, r)
			if tc.Ctrl.Accepted {
				require.IsType(t, &segment.ResponseIndexConfirmationSuccess{}, r)
				rs := r.(*segment.ResponseIndexConfirmationSuccess)
				checkIDs(t, tc.Ctrl.SegmentIndexConfirmation.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.SegmentIndexConfirmation.Base.Index, uint8(rs.Index))
			} else {
				require.IsType(t, &segment.ResponseIndexConfirmationFailure{}, r)
				rs := r.(*segment.ResponseIndexConfirmationFailure)
				checkIDs(t, tc.Ctrl.SegmentIndexConfirmation.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.SegmentIndexConfirmation.Base.Index, uint8(rs.Index))
				require.Equal(t, tc.Ctrl.SegmentIndexConfirmation.ErrorCode, rs.ErrorCode)
			}
		})
	}
}

func TestNewResponseSegmentCleanup(t *testing.T) {
	cases := map[string]struct {
		Ctrl *colibri_mgmt.Response
	}{
		"success": {
			Ctrl: &colibri_mgmt.Response{
				SegmentCleanup: newTestCleanupSuccessResponse(),
				Which:          proto.Response_Which_segmentCleanup,
				Accepted:       true,
			},
		},
		"failure": {
			Ctrl: &colibri_mgmt.Response{
				SegmentCleanup: newTestCleanupFailureResponse(),
				Which:          proto.Response_Which_segmentCleanup,
				Accepted:       false,
				FailedHop:      9,
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ts := util.SecsToTime(1)
			_, err := newResponseSegmentCleanup(tc.Ctrl.SegmentCleanup, tc.Ctrl, ts, nil)
			require.Error(t, err) // no path
			r, err := newResponseSegmentCleanup(tc.Ctrl.SegmentCleanup, tc.Ctrl, ts,
				test.NewTestPath())
			require.NoError(t, err)
			require.NotNil(t, r)
			if tc.Ctrl.Accepted {
				require.IsType(t, &segment.ResponseCleanupSuccess{}, r)
				rs := r.(*segment.ResponseCleanupSuccess)
				checkIDs(t, tc.Ctrl.SegmentCleanup.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.SegmentCleanup.Base.Index, uint8(rs.Index))
			} else {
				require.IsType(t, &segment.ResponseCleanupFailure{}, r)
				rs := r.(*segment.ResponseCleanupFailure)
				checkIDs(t, tc.Ctrl.SegmentCleanup.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.SegmentCleanup.Base.Index, uint8(rs.Index))
				require.Equal(t, tc.Ctrl.SegmentCleanup.ErrorCode, rs.ErrorCode)
			}
		})
	}
}

func TestNewResponseE2ESetup(t *testing.T) {
	cases := map[string]struct {
		Ctrl *colibri_mgmt.Response
	}{
		"success": {
			Ctrl: &colibri_mgmt.Response{
				E2ESetup: newTestE2ESetupSuccessResponse(),
				Which:    proto.Response_Which_e2eSetup,
				Accepted: true,
			},
		},
		"failure": {
			Ctrl: &colibri_mgmt.Response{
				E2ESetup: newTestE2ESetupFailureResponse(),
				Which:    proto.Response_Which_e2eSetup,
				Accepted: false,
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ts := util.SecsToTime(1)
			_, err := newResponseE2ESetup(tc.Ctrl.E2ESetup, tc.Ctrl, ts, nil)
			require.Error(t, err) // no path
			r, err := newResponseE2ESetup(tc.Ctrl.E2ESetup, tc.Ctrl, ts, test.NewTestPath())
			require.NoError(t, err)
			require.NotNil(t, r)
			if tc.Ctrl.Accepted {
				require.IsType(t, &e2e.ResponseSetupSuccess{}, r)
				rs := r.(*e2e.ResponseSetupSuccess)
				checkE2EIDs(t, tc.Ctrl.E2ESetup.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.E2ESetup.Base.Index, uint8(rs.Index))
				require.Equal(t, tc.Ctrl.E2ESetup.Success.Token, rs.Token.ToRaw())
			} else {
				require.IsType(t, &e2e.ResponseSetupFailure{}, r)
				rs := r.(*e2e.ResponseSetupFailure)
				checkE2EIDs(t, tc.Ctrl.E2ESetup.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.E2ESetup.Base.Index, uint8(rs.Index))
				require.Equal(t, tc.Ctrl.E2ESetup.Failure.ErrorCode, rs.ErrorCode)
				require.Len(t, rs.MaxBWs, len(tc.Ctrl.E2ESetup.Failure.AllocationTrail))
			}
		})
	}
}

func TestNewResponseE2EClenaup(t *testing.T) {
	cases := map[string]struct {
		Ctrl *colibri_mgmt.Response
	}{
		"success": {
			Ctrl: &colibri_mgmt.Response{
				E2ECleanup: newTestE2ECleanupSuccessResponse(),
				Which:      proto.Response_Which_e2eCleanup,
				Accepted:   true,
			},
		},
		"failure": {
			Ctrl: &colibri_mgmt.Response{
				E2ECleanup: newTestE2ECleanupFailureResponse(),
				Which:      proto.Response_Which_e2eCleanup,
				Accepted:   false,
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ts := util.SecsToTime(1)
			_, err := newResponseE2EClenaup(tc.Ctrl.E2ECleanup, tc.Ctrl, ts, nil)
			require.Error(t, err) // no path
			r, err := newResponseE2EClenaup(tc.Ctrl.E2ECleanup, tc.Ctrl, ts,
				test.NewTestPath())
			require.NoError(t, err)
			require.NotNil(t, r)
			if tc.Ctrl.Accepted {
				require.IsType(t, &e2e.ResponseCleanupSuccess{}, r)
				rs := r.(*e2e.ResponseCleanupSuccess)
				checkE2EIDs(t, tc.Ctrl.E2ECleanup.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.E2ECleanup.Base.Index, uint8(rs.Index))
			} else {
				require.IsType(t, &e2e.ResponseCleanupFailure{}, r)
				rs := r.(*e2e.ResponseCleanupFailure)
				checkE2EIDs(t, tc.Ctrl.E2ECleanup.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.E2ECleanup.Base.Index, uint8(rs.Index))
				require.Equal(t, tc.Ctrl.E2ECleanup.ErrorCode, rs.ErrorCode)
			}
		})
	}
}
