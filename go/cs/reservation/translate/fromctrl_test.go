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

	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestNewSegmentIDFromCtrl(t *testing.T) {
	ctrl := newID()
	id, err := NewSegmentIDFromCtrl(ctrl)
	require.NoError(t, err)
	rawid := id.ToRaw()
	require.Equal(t, ctrl.ASID, rawid[:6])
	require.Equal(t, ctrl.Suffix, rawid[6:])
}

func TestNewE2EIDFromCtrl(t *testing.T) {
	ctrl := newE2EID()
	id, err := NewE2EIDFromCtrl(ctrl)
	require.NoError(t, err)
	rawid := id.ToRaw()
	require.Equal(t, ctrl.ASID, rawid[:6])
	require.Equal(t, ctrl.Suffix, rawid[6:])
}

func TestNewRequestSegmentSetupFromCtrl(t *testing.T) {
	ctrlMsg := newSetup()
	ts := util.SecsToTime(1)
	r, err := newRequestSegmentSetup(ctrlMsg, ts, nil)
	require.Error(t, err) // missing path
	p := newPath()
	r, err = newRequestSegmentSetup(ctrlMsg, ts, p)
	require.NoError(t, err)
	require.Equal(t, p, r.Path())
	checkRequest(t, ctrlMsg, r, ts)
	require.Equal(t, common.IFIDType(1), r.Ingress)
	require.Equal(t, common.IFIDType(2), r.Egress)
}

func TestNewRequestSegmentTelesSetup(t *testing.T) {
	ctrlMsg := newTelesSetup()
	ts := util.SecsToTime(1)
	r, err := newRequestSegmentTelesSetup(ctrlMsg, ts, nil)
	require.Error(t, err) // path is nil
	r, err = newRequestSegmentTelesSetup(ctrlMsg, ts, newPath())
	require.NoError(t, err)
	checkRequest(t, ctrlMsg.Setup, &r.SetupReq, ts)
	require.Equal(t, xtest.MustParseAS("ff00:cafe:1"), r.BaseID.ASID)
	require.Equal(t, xtest.MustParseHexString("deadbeef"), r.BaseID.Suffix[:])
}

func TestNewRequestSegmentTeardown(t *testing.T) {
	ctrlMsg := newSegmentTeardown()
	ts := util.SecsToTime(1)
	r, err := newRequestSegmentTeardown(ctrlMsg, ts, nil)
	require.Error(t, err) // path is nil
	r, err = newRequestSegmentTeardown(ctrlMsg, ts, newPath())
	require.NoError(t, err)
	checkIDs(t, ctrlMsg.Base.ID, &r.ID)
	require.Equal(t, ctrlMsg.Base.Index, uint8(r.Index))
}

func TestNewRequestSegmentIndexConfirmation(t *testing.T) {
	ctrlMsg := newIndexConfirmation()
	ts := util.SecsToTime(1)
	r, err := newRequestSegmentIndexConfirmation(ctrlMsg, ts, nil)
	require.Error(t, err) // nil path
	r, err = newRequestSegmentIndexConfirmation(ctrlMsg, ts, newPath())
	require.NoError(t, err)
	checkIDs(t, ctrlMsg.Base.ID, &r.ID)
	require.Equal(t, ctrlMsg.Base.Index, uint8(r.Index))
	require.Equal(t, segment.IndexActive, r.State)
}

func TestNewRequestSegmentCleanup(t *testing.T) {
	ctrlMsg := &colibri_mgmt.SegmentCleanup{
		Base: newTestBase(1),
	}
	ts := util.SecsToTime(1)
	r, err := newRequestSegmentCleanup(ctrlMsg, ts, nil)
	require.Error(t, err) // nil path
	r, err = newRequestSegmentCleanup(ctrlMsg, ts, newPath())
	require.NoError(t, err)
	checkIDs(t, ctrlMsg.Base.ID, &r.ID)
	require.Equal(t, ctrlMsg.Base.Index, uint8(r.Index))
}

func TestNewRequestE2ESetup(t *testing.T) {
	ctrlMsg := newE2ESetup()
	ts := util.SecsToTime(1)
	r, err := newRequestE2ESetup(ctrlMsg, ts, nil)
	require.Error(t, err)
	r, err = newRequestE2ESetup(ctrlMsg, ts, newPath())
	require.NoError(t, err)
	checkE2EIDs(t, ctrlMsg.Base.ID, &r.ID)
	require.Equal(t, ctrlMsg.Base.Index, uint8(r.Index))
	require.Equal(t, ctrlMsg.Token, r.Token.ToRaw())
}

func TestNewRequestE2ECleanup(t *testing.T) {
	ctrlMsg := newE2ECleanup()
	ts := util.SecsToTime(1)
	r, err := newRequestE2ECleanup(ctrlMsg, ts, nil)
	require.Error(t, err)
	r, err = newRequestE2ECleanup(ctrlMsg, ts, newPath())
	require.NoError(t, err)
	checkE2EIDs(t, ctrlMsg.Base.ID, &r.ID)
	require.Equal(t, ctrlMsg.Base.Index, uint8(r.Index))
}

func TestNewResponseSegmentSetup(t *testing.T) {
	cases := map[string]struct {
		Ctrl    *colibri_mgmt.SegmentSetupRes
		Success bool
	}{
		"success": {
			Ctrl:    newSegmentSetupSuccessResponse(),
			Success: true,
		},
		"failure": {
			Ctrl:    newSegmentSetupFailureResponse(),
			Success: false,
		},
	}

	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ts := util.SecsToTime(1)
			r, err := newResponseSegmentSetup(tc.Ctrl, 3, ts, nil)
			require.Error(t, err)
			r, err = newResponseSegmentSetup(tc.Ctrl, 3, ts, newPath())
			require.NoError(t, err)
			require.NotNil(t, r)
			if tc.Success {
				require.IsType(t, &segment.ResponseSetupSuccess{}, r)
				rs := r.(*segment.ResponseSetupSuccess)
				checkIDs(t, tc.Ctrl.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.Base.Index, uint8(rs.Index))
				require.Equal(t, tc.Ctrl.Token, rs.Token.ToRaw())
			} else {
				require.IsType(t, &segment.ResponseSetupFailure{}, r)
				rs := r.(*segment.ResponseSetupFailure)
				checkIDs(t, tc.Ctrl.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.Base.Index, uint8(rs.Index))
				checkRequest(t, tc.Ctrl.Failure, &rs.FailedSetup, ts)
			}
		})
	}
}

func TestNewResponseSegmentTeardown(t *testing.T) {
	cases := map[string]struct {
		Ctrl    *colibri_mgmt.SegmentTeardownRes
		Success bool
	}{
		"success": {
			Ctrl:    newSegmentTeardownResponseSuccess(),
			Success: true,
		},
		"failure": {
			Ctrl:    newSegmentTeardownResponseFailure(),
			Success: false,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ts := util.SecsToTime(1)
			r, err := newResponseSegmentTeardown(tc.Ctrl, tc.Success, ts, nil)
			require.Error(t, err) // no path
			r, err = newResponseSegmentTeardown(tc.Ctrl, tc.Success, ts, newPath())
			require.NoError(t, err)
			require.NotNil(t, r)
			if tc.Success {
				require.IsType(t, &segment.TeardownResponseSuccess{}, r)
				rs := r.(*segment.TeardownResponseSuccess)
				checkIDs(t, tc.Ctrl.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.Base.Index, uint8(rs.Index))
			} else {
				require.IsType(t, &segment.TeardownResponseFailure{}, r)
				rs := r.(*segment.TeardownResponseFailure)
				checkIDs(t, tc.Ctrl.Base.ID, &rs.ID)
				require.Equal(t, tc.Ctrl.Base.Index, uint8(rs.Index))
				require.Equal(t, tc.Ctrl.ErrorCode, rs.ErrorCode)
			}
		})
	}
}
