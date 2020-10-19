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
	"github.com/stretchr/testify/require"

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/cs/reservationstorage/backend/mock_backend"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestSumMaxBlockedBW(t *testing.T) {
	cases := map[string]struct {
		blockedBW uint64
		rsvsFcn   func() []*segment.Reservation
		excludeID string
	}{
		"empty": {
			blockedBW: 0,
			rsvsFcn: func() []*segment.Reservation {
				return nil
			},
			excludeID: "ff0000010001beefcafe",
		},
		"one reservation": {
			blockedBW: reservation.BWCls(5).ToKbps(),
			rsvsFcn: func() []*segment.Reservation {
				rsv := testNewRsv(t, "ff00:1:1", "01234567", 1, 2, 5, 5, 5)
				_, err := rsv.NewIndexAtSource(util.SecsToTime(3), 1, 1, 1, 1, reservation.CorePath)
				require.NoError(t, err)
				_, err = rsv.NewIndexAtSource(util.SecsToTime(3), 1, 1, 1, 1, reservation.CorePath)
				require.NoError(t, err)
				return []*segment.Reservation{rsv}
			},
			excludeID: "ff0000010001beefcafe",
		},
		"one reservation but excluded": {
			blockedBW: 0,
			rsvsFcn: func() []*segment.Reservation {
				rsv := testNewRsv(t, "ff00:1:1", "beefcafe", 1, 2, 5, 5, 5)
				_, err := rsv.NewIndexAtSource(util.SecsToTime(3), 1, 1, 1, 1, reservation.CorePath)
				require.NoError(t, err)
				_, err = rsv.NewIndexAtSource(util.SecsToTime(3), 1, 1, 1, 1, reservation.CorePath)
				require.NoError(t, err)
				return []*segment.Reservation{rsv}
			},
			excludeID: "ff0000010001beefcafe",
		},
		"many reservations": {
			blockedBW: 309, // 181 + 128
			rsvsFcn: func() []*segment.Reservation {
				rsv := testNewRsv(t, "ff00:1:1", "beefcafe", 1, 2, 5, 5, 5)
				_, err := rsv.NewIndexAtSource(util.SecsToTime(3), 1, 17, 7, 1,
					reservation.CorePath)
				require.NoError(t, err)
				rsvs := []*segment.Reservation{rsv}

				rsv = testNewRsv(t, "ff00:1:1", "01234567", 1, 2, 5, 5, 5)
				_, err = rsv.NewIndexAtSource(util.SecsToTime(3), 1, 8, 8, 1, reservation.CorePath)
				require.NoError(t, err)
				_, err = rsv.NewIndexAtSource(util.SecsToTime(3), 1, 7, 7, 1, reservation.CorePath)
				require.NoError(t, err)
				rsvs = append(rsvs, rsv)

				rsv = testNewRsv(t, "ff00:1:2", "01234567", 1, 2, 5, 5, 5)
				_, err = rsv.NewIndexAtSource(util.SecsToTime(2), 1, 7, 7, 1, reservation.CorePath)
				require.NoError(t, err)
				rsvs = append(rsvs, rsv)

				return rsvs
			},
			excludeID: "ff0000010001beefcafe",
		},
	}

	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			excludedID, err := reservation.SegmentIDFromRaw(xtest.MustParseHexString(tc.excludeID))
			require.NoError(t, err)
			sum := sumMaxBlockedBW(tc.rsvsFcn(), *excludedID)
			require.Equal(t, tc.blockedBW, sum)
		})
	}
}

func TestAvailableBW(t *testing.T) {
	req := newTestRequest(t, 1, 2, 5, 7)

	cases := map[string]struct {
		availBW uint64
		delta   float64
		req     *segment.SetupReq
		setupDB func(db *mock_backend.MockDB)
	}{
		"empty DB": {
			availBW: 1024,
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
			// as the only reservation in DB has the same ID as the request, the availableBW
			// function should return the same value as with an empty DB.
			availBW: 1024,
			delta:   1,
			req:     req,
			setupDB: func(db *mock_backend.MockDB) {
				db.EXPECT().GetSegmentRsvsFromIFPair(gomock.Any(), &req.Ingress, nil).Return(
					[]*segment.Reservation{
						testNewRsv(t, "ff00:1:1", "beefcafe", 1, 2, 5, 5, 5),
					}, nil)
				db.EXPECT().GetSegmentRsvsFromIFPair(gomock.Any(), nil, &req.Egress).Return(
					[]*segment.Reservation{
						testNewRsv(t, "ff00:1:1", "beefcafe", 1, 2, 5, 5, 5),
					}, nil)
			},
		},
		"other reservation in DB": {
			availBW: 1024 - 64,
			delta:   1,
			req:     req,
			setupDB: func(db *mock_backend.MockDB) {
				db.EXPECT().GetSegmentRsvsFromIFPair(gomock.Any(), &req.Ingress, nil).Return(
					[]*segment.Reservation{
						testNewRsv(t, "ff00:1:1", "beefcafe", 1, 2, 5, 5, 5),
						testNewRsv(t, "ff00:1:2", "beefcafe", 1, 2, 5, 5, 5),
					}, nil)
				db.EXPECT().GetSegmentRsvsFromIFPair(gomock.Any(), nil, &req.Egress).Return(
					[]*segment.Reservation{
						testNewRsv(t, "ff00:1:1", "beefcafe", 1, 2, 5, 5, 5),
						testNewRsv(t, "ff00:1:2", "beefcafe", 1, 2, 5, 5, 5),
					}, nil)
			},
		},
		"change delta": {
			availBW: (1024 - 64) / 2,
			delta:   .5,
			req:     req,
			setupDB: func(db *mock_backend.MockDB) {
				db.EXPECT().GetSegmentRsvsFromIFPair(gomock.Any(), &req.Ingress, nil).Return(
					[]*segment.Reservation{
						testNewRsv(t, "ff00:1:1", "beefcafe", 1, 2, 5, 5, 5),
						testNewRsv(t, "ff00:1:2", "beefcafe", 1, 2, 5, 5, 5),
					}, nil)
				db.EXPECT().GetSegmentRsvsFromIFPair(gomock.Any(), nil, &req.Egress).Return(
					[]*segment.Reservation{
						testNewRsv(t, "ff00:1:1", "beefcafe", 1, 2, 5, 5, 5),
						testNewRsv(t, "ff00:1:2", "beefcafe", 1, 2, 5, 5, 5),
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
			require.NoError(t, err)
			require.Equal(t, tc.availBW, avail)
		})
	}
}

func TestTubeRatio(t *testing.T) {
	cases := map[string]struct {
		tubeRatio      float64
		req            *segment.SetupReq
		setupDB        func(db *mock_backend.MockDB)
		globalCapacity uint64
		interfaces     []uint16
	}{
		"empty": {
			tubeRatio: 1,
			req:       newTestRequest(t, 1, 2, 5, 5),
			setupDB: func(db *mock_backend.MockDB) {
				rsvs := []*segment.Reservation{}
				db.EXPECT().GetAllSegmentRsvs(gomock.Any()).AnyTimes().Return(rsvs, nil)
			},
			globalCapacity: 1024 * 1024,
			interfaces:     []uint16{1, 2, 3},
		},
		"one source, one ingress": {
			tubeRatio: 1,
			req:       newTestRequest(t, 1, 2, 5, 5),
			setupDB: func(db *mock_backend.MockDB) {
				rsvs := []*segment.Reservation{
					testNewRsv(t, "ff00:1:1", "00000001", 1, 2, 5, 5, 5),
				}
				db.EXPECT().GetAllSegmentRsvs(gomock.Any()).AnyTimes().Return(rsvs, nil)
			},
			globalCapacity: 1024 * 1024,
			interfaces:     []uint16{1, 2, 3},
		},
		"one source, two ingress": {
			tubeRatio: .5,
			req:       newTestRequest(t, 1, 2, 3, 3), // 64Kbps
			setupDB: func(db *mock_backend.MockDB) {
				rsvs := []*segment.Reservation{
					testNewRsv(t, "ff00:1:1", "00000001", 1, 2, 5, 3, 3), // 64Kbps
					testNewRsv(t, "ff00:1:1", "00000002", 3, 2, 5, 5, 5), // 128Kbps
				}
				db.EXPECT().GetAllSegmentRsvs(gomock.Any()).AnyTimes().Return(rsvs, nil)
			},
			globalCapacity: 1024 * 1024,
			interfaces:     []uint16{1, 2, 3},
		},
		"two sources, request already present": {
			tubeRatio: .5,
			req:       newTestRequest(t, 1, 2, 5, 5),
			setupDB: func(db *mock_backend.MockDB) {
				rsvs := []*segment.Reservation{
					testNewRsv(t, "ff00:1:1", "beefcafe", 1, 2, 5, 9, 9), // will be ignored
					testNewRsv(t, "ff00:1:1", "00000002", 3, 2, 5, 5, 5),
				}
				db.EXPECT().GetAllSegmentRsvs(gomock.Any()).AnyTimes().Return(rsvs, nil)
			},
			globalCapacity: 1024 * 1024,
			interfaces:     []uint16{1, 2, 3},
		},
		"multiple sources, multiple ingress": {
			tubeRatio: .75,
			req:       newTestRequest(t, 1, 2, 5, 5),
			setupDB: func(db *mock_backend.MockDB) {
				rsvs := []*segment.Reservation{
					testNewRsv(t, "ff00:1:1", "00000001", 1, 2, 5, 5, 5),
					testNewRsv(t, "ff00:1:2", "00000001", 1, 2, 5, 5, 5),
					testNewRsv(t, "ff00:1:1", "00000002", 3, 2, 5, 5, 5),
				}
				db.EXPECT().GetAllSegmentRsvs(gomock.Any()).AnyTimes().Return(rsvs, nil)
			},
			globalCapacity: 1024 * 1024,
			interfaces:     []uint16{1, 2, 3},
		},
		"exceeding ingress capacity": {
			tubeRatio: 10. / 13., // 10 / (10 + 0 + 3)
			req:       newTestRequest(t, 1, 2, 5, 5),
			setupDB: func(db *mock_backend.MockDB) {
				rsvs := []*segment.Reservation{
					testNewRsv(t, "ff00:1:1", "00000001", 1, 2, 5, 5, 5),
					testNewRsv(t, "ff00:1:2", "00000001", 1, 2, 5, 5, 5),
					testNewRsv(t, "ff00:1:1", "00000002", 3, 2, 5, 5, 5),
				}
				db.EXPECT().GetAllSegmentRsvs(gomock.Any()).AnyTimes().Return(rsvs, nil)
			},
			globalCapacity: 10,
			interfaces:     []uint16{1, 2, 3},
		},
		"with many other irrelevant reservations": {
			tubeRatio: .75,
			req:       newTestRequest(t, 1, 2, 5, 5),
			setupDB: func(db *mock_backend.MockDB) {
				rsvs := []*segment.Reservation{
					testNewRsv(t, "ff00:1:1", "00000001", 1, 2, 5, 5, 5),
					testNewRsv(t, "ff00:1:2", "00000001", 1, 2, 5, 5, 5),
					testNewRsv(t, "ff00:1:1", "00000002", 3, 2, 5, 5, 5),
					testNewRsv(t, "ff00:1:3", "00000001", 4, 5, 5, 9, 9),
					testNewRsv(t, "ff00:1:3", "00000002", 4, 5, 5, 9, 9),
					testNewRsv(t, "ff00:1:4", "00000001", 5, 4, 5, 9, 9),
					testNewRsv(t, "ff00:1:4", "00000002", 5, 4, 5, 9, 9),
				}
				db.EXPECT().GetAllSegmentRsvs(gomock.Any()).AnyTimes().Return(rsvs, nil)
			},
			globalCapacity: 1024 * 1024,
			interfaces:     []uint16{1, 2, 3, 4, 5},
		},
	}

	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			adm, finish := newTestAdmitter(t)
			defer finish()

			adm.Capacities = &testCapacities{
				Cap:    tc.globalCapacity,
				Ifaces: tc.interfaces,
			}
			db := adm.DB.(*mock_backend.MockDB)
			tc.setupDB(db)

			ctx := context.Background()
			demPerSrc, err := adm.computeTempDemands(ctx, tc.req.Ingress, tc.req)
			require.NoError(t, err)
			ratio, err := adm.tubeRatio(ctx, tc.req, demPerSrc)
			require.NoError(t, err)
			require.Equal(t, tc.tubeRatio, ratio)
		})
	}
}

func TestLinkRatio(t *testing.T) {
	cases := map[string]struct {
		linkRatio float64
		req       *segment.SetupReq
		setupDB   func(db *mock_backend.MockDB)
	}{
		"empty": {
			linkRatio: 1.,
			req:       testAddAllocTrail(newTestRequest(t, 1, 2, 5, 5), 5, 5),
			setupDB: func(db *mock_backend.MockDB) {
				rsvs := []*segment.Reservation{}
				db.EXPECT().GetAllSegmentRsvs(gomock.Any()).AnyTimes().Return(rsvs, nil)
			},
		},
		"same request": {
			linkRatio: 1.,
			req:       testAddAllocTrail(newTestRequest(t, 1, 2, 5, 5), 5, 5),
			setupDB: func(db *mock_backend.MockDB) {
				rsvs := []*segment.Reservation{
					testNewRsv(t, "ff00:1:1", "beefcafe", 1, 2, 5, 5, 5),
				}
				db.EXPECT().GetAllSegmentRsvs(gomock.Any()).AnyTimes().Return(rsvs, nil)
			},
		},
		"same source": {
			linkRatio: .5,
			req:       testAddAllocTrail(newTestRequest(t, 1, 2, 5, 5), 5, 5),
			setupDB: func(db *mock_backend.MockDB) {
				rsvs := []*segment.Reservation{
					testNewRsv(t, "ff00:1:1", "beefcafe", 1, 2, 5, 5, 5),
					testNewRsv(t, "ff00:1:1", "00000001", 1, 2, 5, 5, 5),
				}
				db.EXPECT().GetAllSegmentRsvs(gomock.Any()).AnyTimes().Return(rsvs, nil)
			},
		},
		"different sources": {
			linkRatio: 1. / 3.,
			req:       testAddAllocTrail(newTestRequest(t, 1, 2, 5, 5), 5, 5),
			setupDB: func(db *mock_backend.MockDB) {
				rsvs := []*segment.Reservation{
					testNewRsv(t, "ff00:1:2", "00000001", 1, 2, 5, 5, 5),
					testNewRsv(t, "ff00:1:3", "00000001", 1, 2, 5, 5, 5),
				}
				db.EXPECT().GetAllSegmentRsvs(gomock.Any()).AnyTimes().Return(rsvs, nil)
			},
		},
		"different egress interface": {
			linkRatio: .5,
			req:       testAddAllocTrail(newTestRequest(t, 1, 2, 5, 5), 5, 5),
			setupDB: func(db *mock_backend.MockDB) {
				rsvs := []*segment.Reservation{
					testNewRsv(t, "ff00:1:1", "00000001", 1, 3, 5, 5, 5),
					// testNewRsv(t, "ff00:1:3", "00000001", 1, 2, 5, 5, 5),
				}
				db.EXPECT().GetAllSegmentRsvs(gomock.Any()).AnyTimes().Return(rsvs, nil)
			},
		},
		"smaller prevBW": {
			linkRatio: 1. / 3.,
			req:       testAddAllocTrail(newTestRequest(t, 1, 2, 5, 5), 3, 3), // 64 Kbps
			setupDB: func(db *mock_backend.MockDB) {
				rsvs := []*segment.Reservation{
					testNewRsv(t, "ff00:1:1", "00000001", 1, 2, 5, 5, 5), // 128 Kbps
				}
				db.EXPECT().GetAllSegmentRsvs(gomock.Any()).AnyTimes().Return(rsvs, nil)
			},
		},
		"bigger prevBW": {
			linkRatio: 2. / 3.,
			req:       testAddAllocTrail(newTestRequest(t, 1, 2, 5, 5), 7, 7), // 256 Kbps
			setupDB: func(db *mock_backend.MockDB) {
				rsvs := []*segment.Reservation{
					testNewRsv(t, "ff00:1:1", "00000001", 1, 2, 5, 5, 5), // 128 Kbps
				}
				db.EXPECT().GetAllSegmentRsvs(gomock.Any()).AnyTimes().Return(rsvs, nil)
			},
		},
	}

	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			adm, finish := newTestAdmitter(t)
			defer finish()

			adm.Capacities = &testCapacities{
				Cap:    1024 * 1024,
				Ifaces: []uint16{1, 2, 3},
			}
			db := adm.DB.(*mock_backend.MockDB)
			tc.setupDB(db)

			ctx := context.Background()
			demsPerSrc, err := adm.computeTempDemands(ctx, tc.req.Ingress, tc.req)
			require.NoError(t, err)
			linkRatio, err := adm.linkRatio(ctx, tc.req, demsPerSrc)
			require.NoError(t, err)
			require.Equal(t, tc.linkRatio, linkRatio)
		})
	}

}

type testCapacities struct {
	Cap    uint64
	Ifaces []uint16
}

var _ base.Capacities = (*testCapacities)(nil)

func (c *testCapacities) IngressInterfaces() []uint16           { return c.Ifaces }
func (c *testCapacities) EgressInterfaces() []uint16            { return c.Ifaces }
func (c *testCapacities) Capacity(from, to uint16) uint64       { return c.Cap }
func (c *testCapacities) CapacityIngress(ingress uint16) uint64 { return c.Cap }
func (c *testCapacities) CapacityEgress(egress uint16) uint64   { return c.Cap }

func newTestAdmitter(t *testing.T) (*StatelessAdmission, func()) {
	mctlr := gomock.NewController(t)

	db := mock_backend.NewMockDB(mctlr)
	return &StatelessAdmission{
		DB: db,
		Capacities: &testCapacities{
			Cap:    1024, // 1MBps
			Ifaces: []uint16{1, 2},
		},
		Delta: 1,
	}, mctlr.Finish
}

// newTestRequest creates a request ID ff00:1:1 beefcafe
func newTestRequest(t *testing.T, ingress, egress uint16,
	minBW, maxBW reservation.BWCls) *segment.SetupReq {

	ID, err := reservation.SegmentIDFromRaw(xtest.MustParseHexString("ff0000010001beefcafe"))
	require.NoError(t, err)
	return &segment.SetupReq{
		Request: segment.Request{
			RequestMetadata: base.RequestMetadata{},
			ID:              *ID,
			Timestamp:       util.SecsToTime(1),
			Ingress:         ingress,
			Egress:          egress,
		},
		MinBW:     minBW,
		MaxBW:     maxBW,
		SplitCls:  2,
		PathProps: reservation.StartLocal | reservation.EndLocal,
	}
}

func testNewRsv(t *testing.T, srcAS string, suffix string, ingress, egress uint16,
	minBW, maxBW, allocBW reservation.BWCls) *segment.Reservation {

	ID, err := reservation.NewSegmentID(xtest.MustParseAS(srcAS),
		xtest.MustParseHexString(suffix))
	require.NoError(t, err)
	rsv := &segment.Reservation{
		ID: *ID,
		Indices: segment.Indices{
			segment.Index{
				Idx:        10,
				Expiration: util.SecsToTime(2),
				MinBW:      minBW,
				MaxBW:      maxBW,
				AllocBW:    allocBW,
			},
		},
		Ingress:      ingress,
		Egress:       egress,
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

// testAddAllocTrail adds an allocation trail to a reservation. The beads parameter represents
// the trail like: alloc0,max0,alloc1,max1,...
func testAddAllocTrail(req *segment.SetupReq, beads ...reservation.BWCls) *segment.SetupReq {
	if len(beads)%2 != 0 {
		panic("the beads must be even")
	}
	for i := 0; i < len(beads); i += 2 {
		beads := reservation.AllocationBead{
			AllocBW: beads[i],
			MaxBW:   beads[i+1],
		}
		req.AllocTrail = append(req.AllocTrail, beads)
	}
	return req
}
