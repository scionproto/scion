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
	ctrlMsg := &colibri_mgmt.SegmentTeardownReq{
		Base: newTestBase(1),
	}
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
	ctrlMsg := newSegmentSuccessResponse()
	ts := util.SecsToTime(1)
	r, err := newResponseSegmentSetup(ctrlMsg, ts, nil)
	require.Error(t, err)
	r, err = newResponseSegmentSetup(ctrlMsg, ts, newPath())
	require.NoError(t, err)
	require.NotNil(t, r)
	require.IsType(t, &segment.ResponseSetupSuccess{}, r)
	rs := r.(*segment.ResponseSetupSuccess)
	checkIDs(t, ctrlMsg.SegmentSetup.Base.ID, &rs.ID)
	require.Equal(t, ctrlMsg.SegmentSetup.Base.Index, uint8(rs.Index))
}
