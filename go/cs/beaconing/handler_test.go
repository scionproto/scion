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

package beaconing_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beaconing"
	"github.com/scionproto/scion/go/cs/beaconing/mock_beaconing"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/serrors"
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

func TestHandlerHandleBeacon(t *testing.T) {
	topoProvider := itopotest.TopoProviderFromFile(t, "testdata/topology-core.json")

	validBeacon := func() beacon.Beacon {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		g := graph.NewDefaultGraph(mctrl)
		return beacon.Beacon{
			Segment: testSegment(g, []common.IFIDType{graph.If_220_X_120_B, graph.If_120_A_110_X}),
			InIfId:  localIF,
		}
	}()

	testCases := map[string]struct {
		Inserter  func(mctrl *gomock.Controller) *mock_beaconing.MockBeaconInserter
		Verifier  func(mctrl *gomock.Controller) *mock_infra.MockVerifier
		Beacon    func(t *testing.T, mctrl *gomock.Controller) beacon.Beacon
		Peer      func() *snet.UDPAddr
		Assertion assert.ErrorAssertionFunc
	}{
		"valid": {
			Inserter: func(mctrl *gomock.Controller) *mock_beaconing.MockBeaconInserter {
				inserter := mock_beaconing.NewMockBeaconInserter(mctrl)
				inserter.EXPECT().PreFilter(gomock.Any()).Return(nil)
				inserter.EXPECT().InsertBeacon(gomock.Any(), validBeacon).Return(
					beacon.InsertStats{}, nil,
				)
				return inserter
			},
			Verifier: func(mctrl *gomock.Controller) *mock_infra.MockVerifier {
				verifier := mock_infra.NewMockVerifier(mctrl)
				verifier.EXPECT().WithServer(gomock.Any()).MaxTimes(2).Return(verifier)
				verifier.EXPECT().WithIA(gomock.Any()).MaxTimes(2).Return(verifier)
				verifier.EXPECT().Verify(gomock.Any(), gomock.Any(),
					gomock.Any()).MaxTimes(2).Return(nil, nil)
				return verifier
			},
			Beacon: func(t *testing.T, mctrl *gomock.Controller) beacon.Beacon {
				return validBeacon
			},
			Peer: func() *snet.UDPAddr {
				return &snet.UDPAddr{
					IA:   addr.IA{},
					Path: testPath(localIF),
				}
			},
			Assertion: assert.NoError,
		},
		"received on unknown interface": {
			Inserter: func(mctrl *gomock.Controller) *mock_beaconing.MockBeaconInserter {
				return mock_beaconing.NewMockBeaconInserter(mctrl)
			},
			Verifier: func(mctrl *gomock.Controller) *mock_infra.MockVerifier {
				return mock_infra.NewMockVerifier(mctrl)
			},
			Beacon: func(t *testing.T, mctrl *gomock.Controller) beacon.Beacon {
				g := graph.NewDefaultGraph(mctrl)
				return beacon.Beacon{
					Segment: testSegment(g, []common.IFIDType{
						graph.If_220_X_120_B, graph.If_120_A_110_X,
					}),
					InIfId: 12,
				}
			},
			Peer: func() *snet.UDPAddr {
				return &snet.UDPAddr{
					IA:   addr.IA{},
					Path: testPath(12),
				}
			},
			Assertion: assert.Error,
		},
		"invalid link type": {
			Inserter: func(mctrl *gomock.Controller) *mock_beaconing.MockBeaconInserter {
				inserter := mock_beaconing.NewMockBeaconInserter(mctrl)
				inserter.EXPECT().PreFilter(gomock.Any()).Return(nil)
				return inserter
			},
			Verifier: func(mctrl *gomock.Controller) *mock_infra.MockVerifier {
				return mock_infra.NewMockVerifier(mctrl)
			},
			Beacon: func(t *testing.T, mctrl *gomock.Controller) beacon.Beacon {
				g := graph.NewDefaultGraph(mctrl)
				return beacon.Beacon{
					Segment: testSegment(g, []common.IFIDType{
						graph.If_220_X_120_B, graph.If_120_A_110_X,
					}),
					InIfId: 42,
				}
			},
			Peer: func() *snet.UDPAddr {
				return &snet.UDPAddr{
					IA:   addr.IA{},
					Path: testPath(42),
				}
			},
			Assertion: assert.Error,
		},
		"invalid origin ISD-AS": {
			Inserter: func(mctrl *gomock.Controller) *mock_beaconing.MockBeaconInserter {
				inserter := mock_beaconing.NewMockBeaconInserter(mctrl)
				inserter.EXPECT().PreFilter(gomock.Any()).Return(nil)
				return inserter
			},
			Verifier: func(mctrl *gomock.Controller) *mock_infra.MockVerifier {
				return mock_infra.NewMockVerifier(mctrl)
			},
			Beacon: func(t *testing.T, mctrl *gomock.Controller) beacon.Beacon {
				g := graph.NewDefaultGraph(mctrl)
				b := beacon.Beacon{
					Segment: testSegment(g, []common.IFIDType{
						graph.If_220_X_120_B, graph.If_120_A_110_X,
					}),
					InIfId: localIF,
				}
				b.Segment.ASEntries[b.Segment.MaxIdx()].Local = xtest.MustParseIA("1-ff00:0:111")
				return b

			},
			Peer: func() *snet.UDPAddr {
				return &snet.UDPAddr{
					IA:   addr.IA{},
					Path: testPath(localIF),
				}
			},
			Assertion: assert.Error,
		},
		"invalid out ISD-AS": {
			Inserter: func(mctrl *gomock.Controller) *mock_beaconing.MockBeaconInserter {
				inserter := mock_beaconing.NewMockBeaconInserter(mctrl)
				inserter.EXPECT().PreFilter(gomock.Any()).Return(nil)
				return inserter
			},
			Verifier: func(mctrl *gomock.Controller) *mock_infra.MockVerifier {
				return mock_infra.NewMockVerifier(mctrl)
			},
			Beacon: func(t *testing.T, mctrl *gomock.Controller) beacon.Beacon {
				g := graph.NewDefaultGraph(mctrl)
				b := beacon.Beacon{
					Segment: testSegment(g, []common.IFIDType{
						graph.If_220_X_120_B, graph.If_120_A_110_X,
					}),
					InIfId: localIF,
				}
				b.Segment.ASEntries[b.Segment.MaxIdx()].Next = xtest.MustParseIA("1-ff00:0:111")
				return b
			},
			Peer: func() *snet.UDPAddr {
				return &snet.UDPAddr{
					IA:   addr.IA{},
					Path: testPath(localIF),
				}
			},
			Assertion: assert.Error,
		},
		"verification error": {
			Inserter: func(mctrl *gomock.Controller) *mock_beaconing.MockBeaconInserter {
				inserter := mock_beaconing.NewMockBeaconInserter(mctrl)
				inserter.EXPECT().PreFilter(gomock.Any()).Return(nil)
				return inserter
			},
			Verifier: func(mctrl *gomock.Controller) *mock_infra.MockVerifier {
				verifier := mock_infra.NewMockVerifier(mctrl)
				verifier.EXPECT().WithServer(gomock.Any()).MaxTimes(2).Return(verifier)
				verifier.EXPECT().WithIA(gomock.Any()).MaxTimes(2).Return(verifier)
				verifier.EXPECT().Verify(gomock.Any(), gomock.Any(),
					gomock.Any()).MaxTimes(2).Return(nil, serrors.New("failed"))
				return verifier
			},
			Beacon: func(t *testing.T, mctrl *gomock.Controller) beacon.Beacon {
				return validBeacon
			},
			Peer: func() *snet.UDPAddr {
				return &snet.UDPAddr{
					IA:   addr.IA{},
					Path: testPath(localIF),
				}
			},
			Assertion: assert.Error,
		},
		"insertion error": {
			Inserter: func(mctrl *gomock.Controller) *mock_beaconing.MockBeaconInserter {
				inserter := mock_beaconing.NewMockBeaconInserter(mctrl)
				inserter.EXPECT().PreFilter(gomock.Any()).Return(nil)
				inserter.EXPECT().InsertBeacon(gomock.Any(), gomock.Any()).Return(
					beacon.InsertStats{}, serrors.New("error"),
				)
				return inserter
			},
			Verifier: func(mctrl *gomock.Controller) *mock_infra.MockVerifier {
				verifier := mock_infra.NewMockVerifier(mctrl)
				verifier.EXPECT().WithServer(gomock.Any()).MaxTimes(2).Return(verifier)
				verifier.EXPECT().WithIA(gomock.Any()).MaxTimes(2).Return(verifier)
				verifier.EXPECT().Verify(gomock.Any(), gomock.Any(),
					gomock.Any()).MaxTimes(2).Return(nil, nil)
				return verifier
			},
			Beacon: func(t *testing.T, mctrl *gomock.Controller) beacon.Beacon {
				return validBeacon
			},
			Peer: func() *snet.UDPAddr {
				return &snet.UDPAddr{
					IA:   addr.IA{},
					Path: testPath(localIF),
				}
			},
			Assertion: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			handler := beaconing.Handler{
				LocalIA:    localIA,
				Inserter:   tc.Inserter(mctrl),
				Interfaces: testInterfaces(topoProvider.Get()),
				Verifier:   tc.Verifier(mctrl),
			}
			err := handler.HandleBeacon(context.Background(),
				tc.Beacon(t, mctrl),
				tc.Peer(),
			)
			tc.Assertion(t, err)
		})
	}
}

func testSegment(g *graph.Graph, ifids []common.IFIDType) *seg.PathSegment {
	pseg := g.Beacon(ifids)
	pseg.ASEntries = pseg.ASEntries[:len(pseg.ASEntries)-1]
	return pseg
}

func testPath(ingressIfid common.IFIDType) *spath.Path {
	path := &spath.Path{
		Raw:    make(common.RawBytes, spath.InfoFieldLength+spath.HopFieldLength),
		HopOff: spath.InfoFieldLength,
	}
	(&spath.InfoField{Hops: 1}).Write(path.Raw[:spath.InfoFieldLength])
	(&spath.HopField{ConsIngress: ingressIfid}).Write(path.Raw[spath.InfoFieldLength:])
	return path
}

func testInterfaces(topo topology.Topology) *ifstate.Interfaces {
	intfs := ifstate.NewInterfaces(topo.IFInfoMap(), ifstate.Config{})
	intfs.Get(graph.If_110_X_120_A).Activate(graph.If_120_A_110_X)
	return intfs
}
