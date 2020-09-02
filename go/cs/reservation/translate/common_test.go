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
	"time"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/ctrl/colibri_mgmt"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/proto"
)

func newTestID() *colibri_mgmt.SegmentReservationID {
	return &colibri_mgmt.SegmentReservationID{
		ASID:   xtest.MustParseHexString("ff00cafe0001"),
		Suffix: xtest.MustParseHexString("deadbeef"),
	}
}

func newTestE2EID() *colibri_mgmt.E2EReservationID {
	return &colibri_mgmt.E2EReservationID{
		ASID:   xtest.MustParseHexString("ff00cafe0001"),
		Suffix: xtest.MustParseHexString("0123456789abcdef0123"),
	}
}

func newTestBase(idx uint8) *colibri_mgmt.SegmentBase {
	return &colibri_mgmt.SegmentBase{
		ID:    newTestID(),
		Index: idx,
	}
}

func newTestE2EBase(idx uint8) *colibri_mgmt.E2EBase {
	return &colibri_mgmt.E2EBase{
		ID:    newTestE2EID(),
		Index: idx,
	}
}

func newTestSetup() *colibri_mgmt.SegmentSetup {
	return &colibri_mgmt.SegmentSetup{
		Base:     newTestBase(1),
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
		InfoField: xtest.MustParseHexString("16ebdb4f0d042500"),
		AllocationTrail: []*colibri_mgmt.AllocationBead{
			{
				AllocBW: 5,
				MaxBW:   6,
			},
		},
	}
}
func newTestSegmentSetupSuccessResponse() *colibri_mgmt.SegmentSetupRes {
	return &colibri_mgmt.SegmentSetupRes{
		Base:  newTestBase(1),
		Which: proto.SegmentSetupResData_Which_token,
		Token: xtest.MustParseHexString("16ebdb4f0d042500003f001002bad1ce003f001002facade"),
	}
}

func newTestSegmentSetupFailureResponse() *colibri_mgmt.SegmentSetupRes {
	return &colibri_mgmt.SegmentSetupRes{
		Base:    newTestBase(1),
		Which:   proto.SegmentSetupResData_Which_failure,
		Failure: newTestSetup(),
	}
}

func newTestTelesSetup() *colibri_mgmt.SegmentTelesSetup {
	return &colibri_mgmt.SegmentTelesSetup{
		Setup:  newTestSetup(),
		BaseID: newTestID(),
	}
}

func newTestSegmentTeardown() *colibri_mgmt.SegmentTeardownReq {
	return &colibri_mgmt.SegmentTeardownReq{
		Base: newTestBase(1),
	}
}

func newTestSegmentTeardownSuccessResponse() *colibri_mgmt.SegmentTeardownRes {
	return &colibri_mgmt.SegmentTeardownRes{
		Base: newTestBase(1),
	}
}

func newTestSegmentTeardownFailureResponse() *colibri_mgmt.SegmentTeardownRes {
	return &colibri_mgmt.SegmentTeardownRes{
		Base:      newTestBase(1),
		ErrorCode: 42,
	}
}

func newTestIndexConfirmation() *colibri_mgmt.SegmentIndexConfirmation {
	return &colibri_mgmt.SegmentIndexConfirmation{
		Base:  newTestBase(2),
		State: proto.ReservationIndexState_active,
	}
}

func newTestIndexConfirmationSuccessResponse() *colibri_mgmt.SegmentIndexConfirmationRes {
	return &colibri_mgmt.SegmentIndexConfirmationRes{
		Base: newTestBase(1),
	}
}

func newTestIndexConfirmationFailureResponse() *colibri_mgmt.SegmentIndexConfirmationRes {
	return &colibri_mgmt.SegmentIndexConfirmationRes{
		Base:      newTestBase(1),
		ErrorCode: 42,
	}
}

func newTestCleanup() *colibri_mgmt.SegmentCleanup {
	return &colibri_mgmt.SegmentCleanup{
		Base: newTestBase(1),
	}
}

func newTestCleanupSuccessResponse() *colibri_mgmt.SegmentCleanupRes {
	return &colibri_mgmt.SegmentCleanupRes{
		Base: newTestBase(1),
	}
}

func newTestCleanupFailureResponse() *colibri_mgmt.SegmentCleanupRes {
	return &colibri_mgmt.SegmentCleanupRes{
		Base:      newTestBase(1),
		ErrorCode: 42,
	}
}

func newTestE2ESetupSuccess() *colibri_mgmt.E2ESetup {
	return &colibri_mgmt.E2ESetup{
		Base:              newTestE2EBase(1),
		SegmentRsvs:       []colibri_mgmt.SegmentReservationID{*newTestID()},
		SegmentRsvASCount: []uint8{3},
		RequestedBW:       5,
		AllocationTrail:   []uint8{5, 5},
		Which:             proto.E2ESetupReqData_Which_success,
		Success: &colibri_mgmt.E2ESetupReqSuccess{
			Token: xtest.MustParseHexString("16ebdb4f0d042500003f001002bad1ce003f001002facade"),
		},
	}
}

func newTestE2ESetupFailure() *colibri_mgmt.E2ESetup {
	return &colibri_mgmt.E2ESetup{
		Base:              newTestE2EBase(1),
		SegmentRsvs:       []colibri_mgmt.SegmentReservationID{*newTestID()},
		SegmentRsvASCount: []uint8{3},
		RequestedBW:       5,
		AllocationTrail:   []uint8{5, 5},
		Which:             proto.E2ESetupReqData_Which_failure,
		Failure: &colibri_mgmt.E2ESetupReqFailure{
			ErrorCode: 66,
		},
	}
}

func newTestE2ESetupSuccessResponse() *colibri_mgmt.E2ESetupRes {
	return &colibri_mgmt.E2ESetupRes{
		Base:  newTestE2EBase(1),
		Which: proto.E2ESetupResData_Which_success,
		Success: &colibri_mgmt.E2ESetupSuccess{
			Token: xtest.MustParseHexString("16ebdb4f0d042500003f001002bad1ce003f001002facade"),
		},
	}
}

func newTestE2ESetupFailureResponse() *colibri_mgmt.E2ESetupRes {
	return &colibri_mgmt.E2ESetupRes{
		Base:  newTestE2EBase(1),
		Which: proto.E2ESetupResData_Which_failure,
		Failure: &colibri_mgmt.E2ESetupFailure{
			ErrorCode:       42,
			AllocationTrail: []uint8{2, 3, 4},
		},
	}
}

func newTestE2ECleanup() *colibri_mgmt.E2ECleanup {
	return &colibri_mgmt.E2ECleanup{
		Base: newTestE2EBase(1),
	}
}

func newTestE2ECleanupSuccessResponse() *colibri_mgmt.E2ECleanupRes {
	return &colibri_mgmt.E2ECleanupRes{
		Base: newTestE2EBase(1),
	}
}

func newTestE2ECleanupFailureResponse() *colibri_mgmt.E2ECleanupRes {
	return &colibri_mgmt.E2ECleanupRes{
		Base:      newTestE2EBase(1),
		ErrorCode: 42,
	}
}

func checkRequest(t *testing.T, segSetup *colibri_mgmt.SegmentSetup, r *segment.SetupReq,
	ts time.Time) {

	t.Helper()
	require.Equal(t, (*segment.Reservation)(nil), r.Reservation)
	require.Equal(t, ts, r.Timestamp)
	checkIDs(t, segSetup.Base.ID, &r.ID)
	require.Equal(t, segSetup.Base.Index, uint8(r.Index))
	require.Equal(t, segSetup.MinBW, uint8(r.MinBW))
	require.Equal(t, segSetup.MaxBW, uint8(r.MaxBW))
	require.Equal(t, segSetup.SplitCls, uint8(r.SplitCls))
	require.Equal(t, reservation.NewPathEndProps(
		segSetup.StartProps.Local, segSetup.StartProps.Transfer,
		segSetup.EndProps.Local, segSetup.EndProps.Transfer), r.PathProps)
	require.Len(t, r.AllocTrail, len(segSetup.AllocationTrail))
	for i := range segSetup.AllocationTrail {
		require.Equal(t, segSetup.AllocationTrail[i].AllocBW, uint8(r.AllocTrail[i].AllocBW))
		require.Equal(t, segSetup.AllocationTrail[i].MaxBW, uint8(r.AllocTrail[i].MaxBW))
	}
}

func checkIDs(t *testing.T, ctrlID *colibri_mgmt.SegmentReservationID, id *reservation.SegmentID) {
	t.Helper()
	expectedID := append(ctrlID.ASID, ctrlID.Suffix...)
	require.Equal(t, expectedID, id.ToRaw())
}

func checkE2EIDs(t *testing.T, ctrlID *colibri_mgmt.E2EReservationID, id *reservation.E2EID) {
	t.Helper()
	expectedID := append(ctrlID.ASID, ctrlID.Suffix...)
	require.Equal(t, expectedID, id.ToRaw())
}
