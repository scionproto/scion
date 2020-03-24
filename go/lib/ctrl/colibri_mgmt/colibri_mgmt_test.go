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

package colibri_mgmt_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

func TestSerializeRoot(t *testing.T) {
	root := &colibri_mgmt.ColibriRequestPayload{
		Which: proto.ColibriRequestPayload_Which_unset,
	}
	buffer, err := root.PackRoot()
	require.NoError(t, err)
	require.Len(t, buffer, 7)
	otherRoot, err := colibri_mgmt.NewFromRaw(buffer)
	require.NoError(t, err)
	require.Equal(t, root.Which, otherRoot.Which)
	otherBuffer, err := otherRoot.PackRoot()
	require.NoError(t, err)
	require.Equal(t, buffer, otherBuffer)
}

// tests serialization for all types of requests
func TestSerializeRequest(t *testing.T) {
	newSegmentSetup := func() *colibri_mgmt.SegmentSetup {
		return &colibri_mgmt.SegmentSetup{
			MinBW:    1,
			MaxBW:    2,
			SplitCls: 3,
			StartProps: colibri_mgmt.PathEndProps{
				Local:    true,
				Transfer: false,
			},
			EndProps: colibri_mgmt.PathEndProps{
				Local:    false,
				Transfer: true,
			},
			AllocationTrail: []*colibri_mgmt.AllocationBeads{
				{
					AllocBW: 5,
					MaxBW:   6,
				},
			},
		}
	}

	testCases := map[string]struct {
		Request *colibri_mgmt.Request
	}{
		"setup": {
			Request: &colibri_mgmt.Request{
				Which:        proto.Request_Which_segmentSetup,
				SegmentSetup: newSegmentSetup(),
			},
		},
		"renewal": {
			Request: &colibri_mgmt.Request{
				Which:          proto.Request_Which_segmentRenewal,
				SegmentRenewal: newSegmentSetup(),
			},
		},
		"teles_setup": {
			Request: &colibri_mgmt.Request{
				Which: proto.Request_Which_segmentTelesSetup,
				SegmentTelesSetup: &colibri_mgmt.SegmentTelesSetup{
					Setup: newSegmentSetup(),
					BaseID: &colibri_mgmt.SegmentReservationID{
						ASID:   xtest.MustParseHexString("ff00cafe0001"),
						Suffix: xtest.MustParseHexString("deadbeef"),
					},
				},
			},
		},
		"teles_renewal": {
			Request: &colibri_mgmt.Request{
				Which: proto.Request_Which_segmentTelesRenewal,
				SegmentTelesRenewal: &colibri_mgmt.SegmentTelesSetup{
					Setup: newSegmentSetup(),
					BaseID: &colibri_mgmt.SegmentReservationID{
						ASID:   xtest.MustParseHexString("ff00cafe0001"),
						Suffix: xtest.MustParseHexString("deadbeef"),
					},
				},
			},
		},
		"teardown": {
			Request: &colibri_mgmt.Request{
				Which:           proto.Request_Which_segmentTeardown,
				SegmentTeardown: &colibri_mgmt.SegmentTeardownReq{},
			},
		},
		"index_confirmation": {
			Request: &colibri_mgmt.Request{
				Which: proto.Request_Which_segmentIndexConfirmation,
				SegmentIndexConfirmation: &colibri_mgmt.SegmentIndexConfirmation{
					Index: 111,
					State: proto.ReservationIndexState_active,
				},
			},
		},
		"cleanup": {
			Request: &colibri_mgmt.Request{
				Which: proto.Request_Which_segmentCleanup,
				SegmentCleanup: &colibri_mgmt.SegmentCleanup{
					ID: &colibri_mgmt.SegmentReservationID{
						ASID:   xtest.MustParseHexString("ff00cafe0001"),
						Suffix: xtest.MustParseHexString("deadbeef"),
					},
					Index: 17,
				},
			},
		},
		"e2esetup": {
			Request: &colibri_mgmt.Request{
				Which: proto.Request_Which_e2eSetup,
				E2ESetup: &colibri_mgmt.E2ESetup{
					Which: proto.E2ESetupData_Which_success,
					Success: &colibri_mgmt.E2ESetupSuccess{
						ReservationID: &colibri_mgmt.E2EReservationID{
							ASID:   xtest.MustParseHexString("ff00cafe0001"),
							Suffix: xtest.MustParseHexString("0123456789abcdef0123456789abcdef"),
						},
						Token: xtest.MustParseHexString("0000"),
					},
				},
			},
		},
		"e2esetup_failure": {
			Request: &colibri_mgmt.Request{
				Which: proto.Request_Which_e2eSetup,
				E2ESetup: &colibri_mgmt.E2ESetup{
					Which: proto.E2ESetupData_Which_failure,
					Failure: &colibri_mgmt.E2ESetupFailure{
						ErrorCode: 1,
						InfoField: xtest.MustParseHexString("fedcba9876543210"),
						MaxBWs:    []uint8{1, 1, 2, 2},
					},
				},
			},
		},
		"e2erenewal": {
			Request: &colibri_mgmt.Request{
				Which: proto.Request_Which_e2eRenewal,
				E2ERenewal: &colibri_mgmt.E2ESetup{
					Which: proto.E2ESetupData_Which_failure,
					Failure: &colibri_mgmt.E2ESetupFailure{
						ErrorCode: 1,
						InfoField: xtest.MustParseHexString("fedcba9876543210"),
						MaxBWs:    []uint8{1, 1, 2, 2},
					},
				},
			},
		},
		"e2ecleanup": {
			Request: &colibri_mgmt.Request{
				Which: proto.Request_Which_e2eCleanup,
				E2ECleanup: &colibri_mgmt.E2ECleanup{
					ReservationID: &colibri_mgmt.E2EReservationID{
						ASID:   xtest.MustParseHexString("ff00cafe0001"),
						Suffix: xtest.MustParseHexString("0123456789abcdef0123456789abcdef"),
					},
				},
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := &colibri_mgmt.ColibriRequestPayload{
				Which:   proto.ColibriRequestPayload_Which_request,
				Request: tc.Request,
			}
			buffer, err := root.PackRoot()
			require.NoError(t, err)
			otherRoot, err := colibri_mgmt.NewFromRaw(buffer)
			require.NoError(t, err)
			otherBuffer, err := otherRoot.PackRoot()
			require.NoError(t, err)
			require.NoError(t, err)
			require.Equal(t, buffer, otherBuffer)
		})
	}
}
