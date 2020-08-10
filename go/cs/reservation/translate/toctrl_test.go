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

	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
	"github.com/stretchr/testify/require"
)

func TestSomething(t *testing.T) {
	_, err := NewMsgFromCtrl(nil, nil)
	require.Error(t, err)
}

func TestNewCtrlSegmentReservationID(t *testing.T) {
	ctrl := newID()
	id, err := NewSegmentIDFromCtrl(ctrl)
	require.NoError(t, err)
	newCtrl := NewCtrlSegmentReservationID(id)
	require.Equal(t, ctrl, newCtrl)
}

func TestNewCtrlE2EReservationID(t *testing.T) {
	ctrl := newE2EID()
	id, err := NewE2EIDFromCtrl(ctrl)
	require.NoError(t, err)
	newCtrl := NewCtrlE2EReservationID(id)
	require.Equal(t, ctrl, newCtrl)
}

func TestNewSegmentSetup(t *testing.T) {
	ctrl := newSetup()
	ts := util.SecsToTime(1)
	r, err := newRequestSegmentSetup(ctrl, ts, newPath())
	require.NoError(t, err)
	newCtrl := newSegmentSetup(r)
	require.Equal(t, ctrl, newCtrl)
}

func TestNewCtrlFromMsg(t *testing.T) {
	cases := map[string]struct {
		Ctrl    *colibri_mgmt.ColibriRequestPayload
		Renewal bool
	}{
		"segment setup": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:        proto.Request_Which_segmentSetup,
					SegmentSetup: newSetup(),
				},
			},
			Renewal: false,
		},
		"segment renewal": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:          proto.Request_Which_segmentRenewal,
					SegmentRenewal: newSetup(),
				},
			},
			Renewal: true,
		},
		"segment teles setup": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:             proto.Request_Which_segmentTelesSetup,
					SegmentTelesSetup: newTelesSetup(),
				},
			},
			Renewal: false,
		},
		"segment teles renewal": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:               proto.Request_Which_segmentTelesRenewal,
					SegmentTelesRenewal: newTelesSetup(),
				},
			},
			Renewal: true,
		},
		"segment teardown": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which: proto.Request_Which_segmentTeardown,
					SegmentTeardown: &colibri_mgmt.SegmentTeardownReq{
						Base: newTestBase(1),
					},
				},
			},
		},
		"segment index confirmation": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:                    proto.Request_Which_segmentIndexConfirmation,
					SegmentIndexConfirmation: newIndexConfirmation(),
				},
			},
		},
		"segment cleanup": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:          proto.Request_Which_segmentCleanup,
					SegmentCleanup: newCleanup(),
				},
			},
		},
		"e2e setup": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:    proto.Request_Which_e2eSetup,
					E2ESetup: newE2ESetup(),
				},
			},
			Renewal: false,
		},
		"e2e renewal": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:      proto.Request_Which_e2eRenewal,
					E2ERenewal: newE2ESetup(),
				},
			},
			Renewal: true,
		},
		"e2e cleanup": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:      proto.Request_Which_e2eCleanup,
					E2ECleanup: newE2ECleanup(),
				},
			},
		},
		"response segment setup success": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					SegmentSetup: newSegmentSetupSuccessResponse(),
					Which:        proto.Response_Which_segmentSetup,
					Accepted:     true,
				},
			},
			Renewal: false,
		},
		"response segment renewal success": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					SegmentRenewal: newSegmentSetupSuccessResponse(),
					Which:          proto.Response_Which_segmentRenewal,
					Accepted:       true,
				},
			},
			Renewal: true,
		},
		"response segment setup failure": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					SegmentSetup: newSegmentSetupFailureResponse(),
					Which:        proto.Response_Which_segmentSetup,
					Accepted:     false,
				},
			},
			Renewal: false,
		},
		"response segment renewal failure": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					SegmentRenewal: newSegmentSetupFailureResponse(),
					Which:          proto.Response_Which_segmentRenewal,
					Accepted:       false,
				},
			},
			Renewal: true,
		},
		// TODO(juagargi) responses
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			msg, err := NewMsgFromCtrl(tc.Ctrl, newPath())
			require.NoError(t, err)
			newCtrl, err := NewCtrlFromMsg(msg, tc.Renewal)
			require.NoError(t, err)
			require.Equal(t, tc.Ctrl, newCtrl)
		})
	}
}
