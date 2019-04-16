// Copyright 2019 Anapaya Systems
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

package beaconing

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/beacon_srv/internal/beaconing/mock_beaconing"
	"github.com/scionproto/scion/go/beacon_srv/internal/ifstate"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

var (
	localIA = xtest.MustParseIA("1-ff00:0:110")
	localIF = graph.If_110_X_120_A
)

// Disable logging in all tests
func TestMain(m *testing.M) {
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}

func TestNewHandler(t *testing.T) {
	Convey("NewHandler crates a correct handler", t, func() {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()

		g := graph.NewDefaultGraph(mctrl)
		bseg := testBeacon(g, []common.IFIDType{graph.If_220_X_120_B, graph.If_120_A_110_X})

		Convey("Correct beacon is inserted", func() {
			inserter := mock_beaconing.NewMockBeaconInserter(mctrl)
			expectedBeacon := beacon.Beacon{Segment: bseg.Segment, InIfId: localIF}
			inserter.EXPECT().InsertBeacons(gomock.Any(), expectedBeacon).Return(nil)

			verifier := mock_infra.NewMockVerifier(mctrl)
			verifier.EXPECT().WithServer(gomock.Any()).MaxTimes(2).Return(verifier)
			verifier.EXPECT().WithSrc(gomock.Any()).MaxTimes(2).Return(verifier)
			verifier.EXPECT().Verify(gomock.Any(), gomock.Any(),
				gomock.Any()).MaxTimes(2).Return(nil)

			handler := NewHandler(localIA, testInterfaces(t), inserter, verifier)
			res := handler.Handle(defaultTestReq(bseg))
			SoMsg("res", res, ShouldEqual, infra.MetricsResultOk)
		})
		Convey("Invalid requests cause an error", func() {
			inserter := mock_beaconing.NewMockBeaconInserter(mctrl)
			verifier := mock_infra.NewMockVerifier(mctrl)

			intfs := testInterfaces(t)
			handler := NewHandler(localIA, intfs, inserter, verifier)
			Convey("Wrong payload type", func() {
				req := infra.NewRequest(context.Background(), &ctrl.Pld{}, nil,
					&snet.Addr{Path: testPath(localIF)}, 0)
				res := handler.Handle(req)
				SoMsg("res", res, ShouldEqual, infra.MetricsErrInternal)
			})
			Convey("Unparsable beacon", func() {
				bseg.Segment.RawSData = nil
				res := handler.Handle(defaultTestReq(bseg))
				SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
			})
			Convey("Invalid path information is caught", func() {
				Convey("Invalid peer address", func() {
					peer := &net.IPNet{
						IP:   net.IPv4zero,
						Mask: net.IPMask([]byte{0, 0, 0, 0}),
					}
					req := infra.NewRequest(context.Background(), bseg, nil, peer, 0)
					res := handler.Handle(req)
					SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
				})
				Convey("Invalid hop field", func() {
					req := infra.NewRequest(context.Background(), bseg, nil,
						&snet.Addr{Path: &spath.Path{}}, 0)
					res := handler.Handle(req)
					SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
				})
				Convey("Invalid unknown interface", func() {
					req := infra.NewRequest(context.Background(), bseg, nil,
						&snet.Addr{Path: testPath(12)}, 0)
					res := handler.Handle(req)
					SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
				})
			})
			Convey("Invalid AS entry information is caught", func() {
				Convey("Invalid link type", func() {
					req := infra.NewRequest(context.Background(), bseg, nil,
						&snet.Addr{Path: testPath(42)}, 0)
					res := handler.Handle(req)
					SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
				})
				Convey("Invalid origin IA", func() {
					bseg := testBeacon(g, []common.IFIDType{graph.If_120_A_110_X})
					asEntry := bseg.Segment.ASEntries[bseg.Segment.MaxAEIdx()]
					asEntry.RawIA = xtest.MustParseIA("1-ff00:0:111").IAInt()
					raw, err := asEntry.Pack()
					xtest.FailOnErr(t, err)
					bseg.Segment.RawASEntries[bseg.Segment.MaxAEIdx()].Blob = raw
					res := handler.Handle(defaultTestReq(bseg))
					SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
				})
				Convey("Invalid hop entry", func() {
					Convey("Invalid out IA", func() {
						bseg := testBeacon(g, []common.IFIDType{graph.If_120_A_110_X})
						asEntry := bseg.Segment.ASEntries[bseg.Segment.MaxAEIdx()]
						asEntry.HopEntries[0].RawOutIA = xtest.MustParseIA("1-ff00:0:111").IAInt()
						raw, err := asEntry.Pack()
						xtest.FailOnErr(t, err)
						bseg.Segment.RawASEntries[bseg.Segment.MaxAEIdx()].Blob = raw
						res := handler.Handle(defaultTestReq(bseg))
						SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
					})
					Convey("Invalid remote out interface", func() {
						bseg := testBeacon(g, []common.IFIDType{graph.If_120_A_110_X})
						asEntry := bseg.Segment.ASEntries[bseg.Segment.MaxAEIdx()]
						asEntry.HopEntries[0].RemoteOutIF = 42
						raw, err := asEntry.Pack()
						xtest.FailOnErr(t, err)
						bseg.Segment.RawASEntries[bseg.Segment.MaxAEIdx()].Blob = raw
						res := handler.Handle(defaultTestReq(bseg))
						SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
					})
				})
				Convey("Verification error", func() {
					verifier := mock_infra.NewMockVerifier(mctrl)
					verifier.EXPECT().WithSrc(gomock.Any()).Return(verifier)
					verifier.EXPECT().WithServer(gomock.Any()).Return(verifier)
					verifier.EXPECT().Verify(gomock.Any(), gomock.Any(),
						gomock.Any()).MaxTimes(2).Return(common.NewBasicError("failed", nil))

					handler := NewHandler(localIA, intfs, inserter, verifier)
					res := handler.Handle(defaultTestReq(bseg))
					SoMsg("res", res, ShouldEqual, infra.MetricsErrInvalid)
				})
				Convey("Insertion error", func() {
					inserter := mock_beaconing.NewMockBeaconInserter(mctrl)
					inserter.EXPECT().InsertBeacons(gomock.Any(),
						gomock.Any()).Return(common.NewBasicError("failed", nil))

					verifier := mock_infra.NewMockVerifier(mctrl)
					verifier.EXPECT().WithServer(gomock.Any()).MaxTimes(2).Return(verifier)
					verifier.EXPECT().WithSrc(gomock.Any()).MaxTimes(2).Return(verifier)
					verifier.EXPECT().Verify(gomock.Any(), gomock.Any(),
						gomock.Any()).MaxTimes(2).Return(nil)

					handler := NewHandler(localIA, intfs, inserter, verifier)
					res := handler.Handle(defaultTestReq(bseg))
					SoMsg("res", res, ShouldEqual, infra.MetricsErrInternal)
				})
			})
		})
	})
}

func defaultTestReq(bseg *seg.Beacon) *infra.Request {
	return infra.NewRequest(context.Background(), bseg, nil, &snet.Addr{Path: testPath(localIF)}, 0)
}

func testBeacon(g *graph.Graph, ifids []common.IFIDType) *seg.Beacon {
	bseg := &seg.Beacon{
		Segment: g.Beacon(ifids),
	}
	bseg.Segment.RawASEntries = bseg.Segment.RawASEntries[:len(bseg.Segment.RawASEntries)-1]
	bseg.Segment.ASEntries = bseg.Segment.ASEntries[:len(bseg.Segment.ASEntries)-1]
	return bseg
}

func testPath(ingressIfid common.IFIDType) *spath.Path {
	path := &spath.Path{
		Raw:    make(common.RawBytes, spath.InfoFieldLength+spath.HopFieldLength),
		HopOff: spath.InfoFieldLength,
	}
	(&spath.HopField{ConsIngress: ingressIfid}).Write(path.Raw[spath.InfoFieldLength:])
	return path
}

func testInterfaces(t *testing.T) *ifstate.Interfaces {
	intfs := ifstate.NewInterfaces(testTopo(t).IFInfoMap, ifstate.Config{})
	intfs.Get(graph.If_110_X_120_A).Activate(graph.If_120_A_110_X)
	return intfs
}

func testTopo(t *testing.T) *topology.Topo {
	topo, err := topology.LoadFromFile("testdata/topology.json")
	xtest.FailOnErr(t, err)
	return topo
}
