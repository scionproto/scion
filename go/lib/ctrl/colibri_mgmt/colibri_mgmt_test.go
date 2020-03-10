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
	"bytes"
	"testing"

	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

func TestSerializeRoot(t *testing.T) {
	root := &colibri_mgmt.ColibriRequestPayload{
		Which: proto.ColibriRequestPayload_Which_unset,
	}
	buffer, err := root.PackRoot()
	if err != nil {
		t.Fatalf("Error serializing root: %v", err)
	}
	if len(buffer) != 7 {
		t.Fatalf("Expected 15 bytes, got %d", len(buffer))
	}
	copy, err := colibri_mgmt.NewFromRaw(buffer)
	if err != nil {
		t.Fatalf("Error deserializing buffer: %v", err)
	}
	if copy.Which != root.Which {
		t.Fatalf("Not equal")
	}
	otherBuffer, err := copy.PackRoot()
	if err != nil {
		t.Fatalf("Error serializing root: %v", err)
	}
	if bytes.Compare(buffer, otherBuffer) != 0 {
		t.Fatalf("Serialized message not equal")
	}
}

// tests serialization for all types of requests
func TestSerializeRequest(t *testing.T) {
	setup := &colibri_mgmt.SegmentSetup{
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
	request := &colibri_mgmt.Request{
		Which:        proto.Request_Which_segmentSetup,
		SegmentSetup: setup,
	}
	buildRequestAndCheck(t, request)

	request = &colibri_mgmt.Request{
		Which:          proto.Request_Which_segmentRenewal,
		SegmentRenewal: setup,
	}
	buildRequestAndCheck(t, request)

	segmentTelesSetup := &colibri_mgmt.SegmentTelesSetup{
		Setup: setup,
		BaseID: &colibri_mgmt.SegmentReservationID{
			ASID:   xtest.MustParseHexString("ff00cafe0001"),
			Suffix: xtest.MustParseHexString("deadbeef"),
		},
	}
	request = &colibri_mgmt.Request{
		Which:             proto.Request_Which_segmentTelesSetup,
		SegmentTelesSetup: segmentTelesSetup,
	}
	buildRequestAndCheck(t, request)

	request = &colibri_mgmt.Request{
		Which:               proto.Request_Which_segmentTelesRenewal,
		SegmentTelesRenewal: segmentTelesSetup,
	}
	buildRequestAndCheck(t, request)

	request = &colibri_mgmt.Request{
		Which:           proto.Request_Which_segmentTeardown,
		SegmentTeardown: &colibri_mgmt.SegmentTeardownReq{},
	}
	buildRequestAndCheck(t, request)

	segmentIndexConfirmation := &colibri_mgmt.SegmentIndexConfirmation{
		Index: 111,
		State: proto.ReservationIndexState_active,
	}
	request = &colibri_mgmt.Request{
		Which:                    proto.Request_Which_segmentIndexConfirmation,
		SegmentIndexConfirmation: segmentIndexConfirmation,
	}
	buildRequestAndCheck(t, request)

	segmentCleanup := &colibri_mgmt.SegmentCleanup{
		ID: &colibri_mgmt.SegmentReservationID{
			ASID:   xtest.MustParseHexString("ff00cafe0001"),
			Suffix: xtest.MustParseHexString("deadbeef"),
		},
		Index: 17,
	}
	request = &colibri_mgmt.Request{
		Which:          proto.Request_Which_segmentCleanup,
		SegmentCleanup: segmentCleanup,
	}
	buildRequestAndCheck(t, request)

	e2eSetup := &colibri_mgmt.E2ESetup{
		Which: proto.E2ESetupData_Which_success,
		Success: &colibri_mgmt.E2ESetupSuccess{
			ReservationID: &colibri_mgmt.E2EReservationID{
				ASID:   xtest.MustParseHexString("ff00cafe0001"),
				Suffix: xtest.MustParseHexString("0123456789abcdef0123456789abcdef"),
			},
			Token: xtest.MustParseHexString("0000"),
		},
	}
	request = &colibri_mgmt.Request{
		Which:    proto.Request_Which_e2eSetup,
		E2ESetup: e2eSetup,
	}
	buildRequestAndCheck(t, request)
	e2eSetup = &colibri_mgmt.E2ESetup{
		Which: proto.E2ESetupData_Which_failure,
		Failure: &colibri_mgmt.E2ESetupFailure{
			ErrorCode: 1,
			InfoField: xtest.MustParseHexString("fedcba9876543210"),
			MaxBWs:    []uint8{1, 1, 2, 2},
		},
	}
	request = &colibri_mgmt.Request{
		Which:    proto.Request_Which_e2eSetup,
		E2ESetup: e2eSetup,
	}
	buildRequestAndCheck(t, request)

	request = &colibri_mgmt.Request{
		Which:      proto.Request_Which_e2eRenewal,
		E2ERenewal: e2eSetup,
	}
	buildRequestAndCheck(t, request)

	e2eCleanup := &colibri_mgmt.E2ECleanup{
		ReservationID: &colibri_mgmt.E2EReservationID{
			ASID:   xtest.MustParseHexString("ff00cafe0001"),
			Suffix: xtest.MustParseHexString("0123456789abcdef0123456789abcdef"),
		},
	}
	request = &colibri_mgmt.Request{
		Which:      proto.Request_Which_e2eCleanup,
		E2ECleanup: e2eCleanup,
	}
	buildRequestAndCheck(t, request)
}

func buildRequestAndCheck(t *testing.T, request *colibri_mgmt.Request) {
	root := &colibri_mgmt.ColibriRequestPayload{
		Which:   proto.ColibriRequestPayload_Which_request,
		Request: request,
	}
	serializeAndCompareRoot(t, root)
}

func serializeAndCompareRoot(t *testing.T, root *colibri_mgmt.ColibriRequestPayload) {
	buffer, err := root.PackRoot()
	if err != nil {
		t.Fatalf("Error serializing root: %v", err)
	}
	copy, err := colibri_mgmt.NewFromRaw(buffer)
	if err != nil {
		t.Fatalf("Error deserializing root: %v", err)
	}
	copyBuffer, err := copy.PackRoot()
	if err != nil {
		t.Fatalf("Error serializing copy: %v", err)
	}
	if bytes.Compare(buffer, copyBuffer) != 0 {
		t.Fatalf("The colibri message is different after (de)serialization.\nOriginal: %v\n"+
			"Recreated one: %v", root, copy)
	}
}
