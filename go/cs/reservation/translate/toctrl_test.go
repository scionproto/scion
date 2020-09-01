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

	"github.com/scionproto/scion/go/cs/reservation/segmenttest"
	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

func TestSomething(t *testing.T) {
	_, err := NewMsgFromCtrl(nil, nil)
	require.Error(t, err)
}

func TestNewCtrlSegmentReservationID(t *testing.T) {
	ctrl := newTestID()
	id, err := NewSegmentIDFromCtrl(ctrl)
	require.NoError(t, err)
	newCtrl := NewCtrlSegmentReservationID(id)
	require.Equal(t, ctrl, newCtrl)
}

func TestNewCtrlE2EReservationID(t *testing.T) {
	ctrl := newTestE2EID()
	id, err := NewE2EIDFromCtrl(ctrl)
	require.NoError(t, err)
	newCtrl := NewCtrlE2EReservationID(id)
	require.Equal(t, ctrl, newCtrl)
}

func TestNewSegmentSetup(t *testing.T) {
	ctrl := newTestSetup()
	ts := util.SecsToTime(1)
	r, err := newRequestSegmentSetup(ctrl, ts, segmenttest.NewTestPath())
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
					SegmentSetup: newTestSetup(),
				},
			},
			Renewal: false,
		},
		"segment renewal": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:          proto.Request_Which_segmentRenewal,
					SegmentRenewal: newTestSetup(),
				},
			},
			Renewal: true,
		},
		"segment teles setup": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:             proto.Request_Which_segmentTelesSetup,
					SegmentTelesSetup: newTestTelesSetup(),
				},
			},
			Renewal: false,
		},
		"segment teles renewal": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:               proto.Request_Which_segmentTelesRenewal,
					SegmentTelesRenewal: newTestTelesSetup(),
				},
			},
			Renewal: true,
		},
		"segment teardown": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:           proto.Request_Which_segmentTeardown,
					SegmentTeardown: newTestSegmentTeardown(),
				},
			},
		},
		"segment index confirmation": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:                    proto.Request_Which_segmentIndexConfirmation,
					SegmentIndexConfirmation: newTestIndexConfirmation(),
				},
			},
		},
		"segment cleanup": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:          proto.Request_Which_segmentCleanup,
					SegmentCleanup: newTestCleanup(),
				},
			},
		},
		"e2e setup success": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:    proto.Request_Which_e2eSetup,
					E2ESetup: newTestE2ESetupSuccess(),
				},
			},
			Renewal: false,
		},
		"e2e setup failure": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:    proto.Request_Which_e2eSetup,
					E2ESetup: newTestE2ESetupFailure(),
				},
			},
			Renewal: false,
		},
		"e2e renewal success": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:      proto.Request_Which_e2eRenewal,
					E2ERenewal: newTestE2ESetupSuccess(),
				},
			},
			Renewal: true,
		},
		"e2e renewal failure": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:      proto.Request_Which_e2eRenewal,
					E2ERenewal: newTestE2ESetupFailure(),
				},
			},
			Renewal: true,
		},
		"e2e cleanup": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_request,
				Request: &colibri_mgmt.Request{
					Which:      proto.Request_Which_e2eCleanup,
					E2ECleanup: newTestE2ECleanup(),
				},
			},
		},
		"response segment setup success": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					SegmentSetup: newTestSegmentSetupSuccessResponse(),
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
					SegmentRenewal: newTestSegmentSetupSuccessResponse(),
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
					SegmentSetup: newTestSegmentSetupFailureResponse(),
					Which:        proto.Response_Which_segmentSetup,
					Accepted:     false,
					FailedHop:    3,
				},
			},
			Renewal: false,
		},
		"response segment renewal failure": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					SegmentRenewal: newTestSegmentSetupFailureResponse(),
					Which:          proto.Response_Which_segmentRenewal,
					Accepted:       false,
					FailedHop:      3,
				},
			},
			Renewal: true,
		},
		"response segment teardown success": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					SegmentTeardown: newTestSegmentTeardownSuccessResponse(),
					Which:           proto.Response_Which_segmentTeardown,
					Accepted:        true,
				},
			},
		},
		"response segment teardown failure": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					SegmentTeardown: newTestSegmentTeardownFailureResponse(),
					Which:           proto.Response_Which_segmentTeardown,
					Accepted:        false,
					FailedHop:       3,
				},
			},
		},
		"response segment index confirmation success": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					SegmentIndexConfirmation: newTestIndexConfirmationSuccessResponse(),
					Which:                    proto.Response_Which_segmentIndexConfirmation,
					Accepted:                 true,
				},
			},
		},
		"response segment index confirmation failure": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					SegmentIndexConfirmation: newTestIndexConfirmationFailureResponse(),
					Which:                    proto.Response_Which_segmentIndexConfirmation,
					Accepted:                 false,
					FailedHop:                3,
				},
			},
		},
		"response segment cleanup success": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					SegmentCleanup: newTestCleanupSuccessResponse(),
					Which:          proto.Response_Which_segmentCleanup,
					Accepted:       true,
				},
			},
		},
		"response segment cleanup failure": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					SegmentCleanup: newTestCleanupFailureResponse(),
					Which:          proto.Response_Which_segmentCleanup,
					Accepted:       false,
					FailedHop:      3,
				},
			},
		},
		"response e2e setup success": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					E2ESetup: newTestE2ESetupSuccessResponse(),
					Which:    proto.Response_Which_e2eSetup,
					Accepted: true,
				},
			},
			Renewal: false,
		},
		"response e2e renewal success": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					E2ERenewal: newTestE2ESetupSuccessResponse(),
					Which:      proto.Response_Which_e2eRenewal,
					Accepted:   true,
				},
			},
			Renewal: true,
		},
		"response e2e setup failure": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					E2ESetup:  newTestE2ESetupFailureResponse(),
					Which:     proto.Response_Which_e2eSetup,
					Accepted:  false,
					FailedHop: 3,
				},
			},
			Renewal: false,
		},
		"response e2e renewal failure": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					E2ERenewal: newTestE2ESetupFailureResponse(),
					Which:      proto.Response_Which_e2eRenewal,
					Accepted:   false,
					FailedHop:  3,
				},
			},
			Renewal: true,
		},
		"response e2e cleanup success": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					E2ECleanup: newTestE2ECleanupSuccessResponse(),
					Which:      proto.Response_Which_e2eCleanup,
					Accepted:   true,
				},
			},
		},
		"response e2e cleanup failure": {
			Ctrl: &colibri_mgmt.ColibriRequestPayload{
				Which: proto.ColibriRequestPayload_Which_response,
				Response: &colibri_mgmt.Response{
					E2ECleanup: newTestE2ECleanupFailureResponse(),
					Which:      proto.Response_Which_e2eCleanup,
					Accepted:   false,
					FailedHop:  3,
				},
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			msg, err := NewMsgFromCtrl(tc.Ctrl, segmenttest.NewTestPath())
			require.NoError(t, err)
			newCtrl, err := NewCtrlFromMsg(msg, tc.Renewal)
			require.NoError(t, err)
			require.Equal(t, tc.Ctrl, newCtrl)
		})
	}
}
