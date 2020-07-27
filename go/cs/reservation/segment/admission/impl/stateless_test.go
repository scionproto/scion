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

package impl

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/cs/reservationstorage/backend/mock_backend"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/stretchr/testify/require"
)

func TestSumMaxBlockedBW(t *testing.T) {
	//
}

func TestAvailableBW(t *testing.T) {
	req := newTestRequest(t)

	cases := map[string]struct {
		availBW uint64
		success bool
		delta   float64
		req     *segment.SetupReq
		setupDB func(db *mock_backend.MockDB)
	}{
		"empty DB": {
			availBW: 1024,
			success: true,
			delta:   1,
			req:     req,
			setupDB: func(db *mock_backend.MockDB) {
				db.EXPECT().GetSegmentRsvsFromIFPair(gomock.Any(), &req.Ingress, nil).Return(
					nil, nil)
				db.EXPECT().GetSegmentRsvsFromIFPair(gomock.Any(), nil, &req.Egress).Return(
					nil, nil)
			},
		},
		"this reservation in DB": {
			availBW: 1024,
			success: true,
			delta:   1,
			req:     req,
			setupDB: func(db *mock_backend.MockDB) {
				db.EXPECT().GetSegmentRsvsFromIFPair(gomock.Any(), &req.Ingress, nil).Return(
					[]*segment.Reservation{
						testNewRsv(t, "ff00:1:1", "beefcafe"),
					}, nil)
				db.EXPECT().GetSegmentRsvsFromIFPair(gomock.Any(), nil, &req.Egress).Return(
					[]*segment.Reservation{
						testNewRsv(t, "ff00:1:1", "beefcafe"),
					}, nil)
			},
		},
		"other reservation in DB": {
			availBW: 1024 - 64,
			success: true,
			delta:   1,
			req:     req,
			setupDB: func(db *mock_backend.MockDB) {
				db.EXPECT().GetSegmentRsvsFromIFPair(gomock.Any(), &req.Ingress, nil).Return(
					[]*segment.Reservation{
						testNewRsv(t, "ff00:1:1", "beefcafe"),
						testNewRsv(t, "ff00:1:2", "beefcafe"),
					}, nil)
				db.EXPECT().GetSegmentRsvsFromIFPair(gomock.Any(), nil, &req.Egress).Return(
					[]*segment.Reservation{
						testNewRsv(t, "ff00:1:1", "beefcafe"),
						testNewRsv(t, "ff00:1:2", "beefcafe"),
					}, nil)
			},
		},
		"change delta": {
			availBW: (1024 - 64) / 2,
			success: true,
			delta:   .5,
			req:     req,
			setupDB: func(db *mock_backend.MockDB) {
				db.EXPECT().GetSegmentRsvsFromIFPair(gomock.Any(), &req.Ingress, nil).Return(
					[]*segment.Reservation{
						testNewRsv(t, "ff00:1:1", "beefcafe"),
						testNewRsv(t, "ff00:1:2", "beefcafe"),
					}, nil)
				db.EXPECT().GetSegmentRsvsFromIFPair(gomock.Any(), nil, &req.Egress).Return(
					[]*segment.Reservation{
						testNewRsv(t, "ff00:1:1", "beefcafe"),
						testNewRsv(t, "ff00:1:2", "beefcafe"),
					}, nil)
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			adm, finish := newTestAdmitter(t)
			defer finish()

			adm.Delta = tc.delta
			ctx := context.Background()
			db := adm.DB.(*mock_backend.MockDB)
			tc.setupDB(db)
			avail, err := adm.availableBW(ctx, tc.req)
			if tc.success {
				require.NoError(t, err)
				require.Equal(t, tc.availBW, avail)
			} else {
				require.Error(t, err)
			}
		})
	}
}

type testCapacities struct {
	Cap    uint64
	Ifaces []common.IFIDType
}

var _ base.Capacities = (*testCapacities)(nil)

func (c *testCapacities) IngressInterfaces() []common.IFIDType           { return c.Ifaces }
func (c *testCapacities) EgressInterfaces() []common.IFIDType            { return c.Ifaces }
func (c *testCapacities) Capacity(from, to common.IFIDType) uint64       { return c.Cap }
func (c *testCapacities) CapacityIngress(ingress common.IFIDType) uint64 { return c.Cap }
func (c *testCapacities) CapacityEgress(egress common.IFIDType) uint64   { return c.Cap }

func newTestAdmitter(t *testing.T) (*StatelessAdmission, func()) {
	mctlr := gomock.NewController(t)

	db := mock_backend.NewMockDB(mctlr)
	return &StatelessAdmission{
		DB: db,
		Capacities: &testCapacities{
			Cap:    1024, // 1MBps
			Ifaces: []common.IFIDType{1, 2},
		},
		Delta: 1,
	}, mctlr.Finish
}

func newTestRequest(t *testing.T) *segment.SetupReq {
	ID, err := reservation.SegmentIDFromRaw(xtest.MustParseHexString("ff0000010001beefcafe"))
	require.NoError(t, err)
	return &segment.SetupReq{
		Request: segment.Request{
			RequestMetadata: base.RequestMetadata{},
			ID:              *ID,
			Timestamp:       util.SecsToTime(1),
			Ingress:         1,
			Egress:          2,
		},
		MinBW:     5, // 64KBps
		MaxBW:     7, // 128
		SplitCls:  2,
		PathProps: reservation.StartLocal | reservation.EndLocal,
	}
}

func testNewRsv(t *testing.T, srcAS string, suffix string) *segment.Reservation {
	ID, err := reservation.NewSegmentID(xtest.MustParseAS(srcAS),
		xtest.MustParseHexString(suffix))
	require.NoError(t, err)
	rsv := &segment.Reservation{
		ID: *ID,
		Indices: segment.Indices{
			segment.Index{
				Idx:        10,
				Expiration: util.SecsToTime(2),
				MinBW:      5,
				MaxBW:      7,
				AllocBW:    5,
			},
		},
		Ingress:      1,
		Egress:       2,
		PathType:     reservation.UpPath,
		PathEndProps: reservation.StartLocal | reservation.EndLocal | reservation.EndTransfer,
		TrafficSplit: 2,
	}
	err = rsv.SetIndexConfirmed(10)
	require.NoError(t, err)
	err = rsv.SetIndexActive(10)
	require.NoError(t, err)
	return rsv
}
