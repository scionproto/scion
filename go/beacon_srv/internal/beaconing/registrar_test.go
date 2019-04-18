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
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/beacon_srv/internal/beaconing/mock_beaconing"
	"github.com/scionproto/scion/go/beacon_srv/internal/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/proto"
)

func TestRegistrarRun(t *testing.T) {
	mac, err := scrypto.InitMac(make(common.RawBytes, 16))
	xtest.FailOnErr(t, err)
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	xtest.FailOnErr(t, err)

	tests := []struct {
		name          string
		segType       proto.PathSegType
		fn            string
		beacons       [][]common.IFIDType
		inactivePeers map[common.IFIDType]bool
		remotePS      bool
	}{
		{
			name:    "Core segment",
			segType: proto.PathSegType_core,
			fn:      topoCore,
			beacons: [][]common.IFIDType{
				{graph.If_120_A_110_X},
				{graph.If_130_B_120_A, graph.If_120_A_110_X},
			},
		},
		{
			name:          "Up segment",
			segType:       proto.PathSegType_up,
			fn:            topoNonCore,
			inactivePeers: map[common.IFIDType]bool{graph.If_111_C_121_X: true},
			beacons: [][]common.IFIDType{
				{graph.If_120_X_111_B},
				{graph.If_130_B_120_A, graph.If_120_X_111_B},
			},
		},
		{
			name:          "Down segment",
			segType:       proto.PathSegType_down,
			fn:            topoNonCore,
			inactivePeers: map[common.IFIDType]bool{graph.If_111_C_121_X: true},
			beacons: [][]common.IFIDType{
				{graph.If_120_X_111_B},
				{graph.If_130_B_120_A, graph.If_120_X_111_B},
			},
			remotePS: true,
		},
	}
	for _, test := range tests {
		Convey("Run registers a verifiable "+test.name+" to the correct path server", t, func() {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			setupItopo(t, test.fn)
			g := graph.NewDefaultGraph(mctrl)
			intfs := ifstate.NewInterfaces(itopo.Get().IFInfoMap, ifstate.Config{})
			msgr := mock_infra.NewMockMessenger(mctrl)
			provider := mock_beaconing.NewMockSegmentProvider(mctrl)
			r, err := NewRegistrar(intfs, test.segType, mac, provider, msgr,
				Config{
					MTU:    uint16(itopo.Get().MTU),
					Signer: testSigner(t, priv),
				},
			)
			SoMsg("err", err, ShouldBeNil)
			provider.EXPECT().SegmentsToRegister(gomock.Any(), test.segType).DoAndReturn(
				func(_, _ interface{}) (<-chan beacon.BeaconOrErr, error) {
					res := make(chan beacon.BeaconOrErr, len(test.beacons))
					for _, desc := range test.beacons {
						res <- testBeaconOrErr(g, desc)
					}
					close(res)
					return res, nil
				})
			segMu := sync.Mutex{}
			var sent []struct {
				Reg  *path_mgmt.SegReg
				Addr *snet.Addr
			}
			msgr.EXPECT().SendSegReg(gomock.Any(), gomock.Any(), gomock.Any(),
				gomock.Any()).Times(len(test.beacons)).DoAndReturn(
				func(_, isegreg, iaddr, _ interface{}) error {
					segMu.Lock()
					defer segMu.Unlock()
					s := struct {
						Reg  *path_mgmt.SegReg
						Addr *snet.Addr
					}{
						Reg:  isegreg.(*path_mgmt.SegReg),
						Addr: iaddr.(*snet.Addr),
					}
					sent = append(sent, s)
					return nil
				},
			)
			for ifid, intf := range intfs.All() {
				if test.inactivePeers[ifid] {
					continue
				}
				intf.Activate(42)
			}
			r.Run(context.Background())
			SoMsg("Sent", len(sent), ShouldEqual, len(test.beacons))
			for segIdx, s := range sent {
				SoMsg("Len", len(s.Reg.Recs), ShouldEqual, 1)
				pseg := s.Reg.Recs[0].Segment
				Convey(fmt.Sprintf("Segment %d is verifiable", segIdx), func() {
					err := pseg.VerifyASEntry(context.Background(),
						segVerifier(pub), pseg.MaxAEIdx())
					SoMsg("err", err, ShouldBeNil)
				})
				Convey(fmt.Sprintf("Segment %d is terminated", segIdx), func() {
					for hopEntryIdx, entry := range pseg.ASEntries[pseg.MaxAEIdx()].HopEntries {
						Convey(fmt.Sprintf("Segment %d Entry %d", segIdx, hopEntryIdx), func() {
							// Terminated.
							SoMsg("OutIA", entry.OutIA().IsZero(), ShouldBeTrue)
							SoMsg("OutIF", entry.RemoteOutIF, ShouldBeZeroValue)
							hopF, err := spath.HopFFromRaw(entry.RawHopField)
							SoMsg("err", err, ShouldBeNil)
							SoMsg("egress", hopF.ConsEgress, ShouldBeZeroValue)
							// Ingress set correctly.
							intf := intfs.Get(hopF.ConsIngress)
							topoInfo := intf.TopoInfo()
							SoMsg("ingress", intf, ShouldNotBeNil)
							SoMsg("InIA", entry.InIA(), ShouldResemble, topoInfo.ISD_AS)
							SoMsg("InIF", entry.RemoteInIF, ShouldEqual, topoInfo.RemoteIFID)
							if hopEntryIdx > 0 {
								SoMsg("Peer", topoInfo.LinkType, ShouldEqual,
									proto.LinkType_peer)
							}
						})
					}
				})
				Convey(fmt.Sprintf("Segment %d is sent to the correct PS", segIdx), func() {
					if !test.remotePS {
						SoMsg("IA", s.Addr.IA, ShouldResemble, itopo.Get().ISD_AS)
						a := itopo.Get().PS[fmt.Sprintf("ps%s-1", s.Addr.IA.FileFmt(false))]
						SoMsg("Host", s.Addr.Host, ShouldResemble, a.PublicAddr(a.Overlay))
						return
					}
					SoMsg("IA", s.Addr.IA, ShouldResemble, pseg.FirstIA())
					SoMsg("Host", s.Addr.Host.L3, ShouldResemble, addr.SvcPS)
					hopF, err := s.Addr.Path.GetHopField(s.Addr.Path.HopOff)
					SoMsg("err", err, ShouldBeNil)
					SoMsg("HopField", []uint8(hopF.Pack()), ShouldResemble,
						pseg.ASEntries[pseg.MaxAEIdx()].HopEntries[0].RawHopField)
					a := itopo.Get().IFInfoMap[hopF.ConsIngress].InternalAddrs
					SoMsg("Next", s.Addr.NextHop, ShouldResemble, a.PublicOverlay(a.Overlay))
				})
			}
		})
	}
	Convey("Run drains the channel", t, func() {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		setupItopo(t, topoCore)
		intfs := ifstate.NewInterfaces(itopo.Get().IFInfoMap, ifstate.Config{})
		xtest.FailOnErr(t, err)
		msgr := mock_infra.NewMockMessenger(mctrl)
		provider := mock_beaconing.NewMockSegmentProvider(mctrl)
		r, err := NewRegistrar(intfs, proto.PathSegType_core, mac, provider, msgr,
			Config{
				MTU:    uint16(itopo.Get().MTU),
				Signer: testSigner(t, priv),
			},
		)
		SoMsg("err", err, ShouldBeNil)
		res := make(chan beacon.BeaconOrErr, 3)
		provider.EXPECT().SegmentsToRegister(gomock.Any(), proto.PathSegType_core).DoAndReturn(
			func(_, _ interface{}) (<-chan beacon.BeaconOrErr, error) {
				for i := 0; i < 3; i++ {
					res <- beacon.BeaconOrErr{Err: errors.New("Invalid beacon")}
				}
				close(res)
				return res, nil
			})
		r.Run(context.Background())
		select {
		case b := <-res:
			SoMsg("Err", b, ShouldBeZeroValue)
		default:
			SoMsg("Must not block", true, ShouldBeFalse)
		}
	})
	Convey("Faulty beacons are not sent", t, func() {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		setupItopo(t, topoNonCore)
		g := graph.NewDefaultGraph(mctrl)
		intfs := ifstate.NewInterfaces(itopo.Get().IFInfoMap, ifstate.Config{})
		xtest.FailOnErr(t, err)
		msgr := mock_infra.NewMockMessenger(mctrl)
		provider := mock_beaconing.NewMockSegmentProvider(mctrl)
		r, err := NewRegistrar(intfs, proto.PathSegType_core, mac, provider, msgr,
			Config{
				MTU:    uint16(itopo.Get().MTU),
				Signer: testSigner(t, priv),
			},
		)
		SoMsg("err", err, ShouldBeNil)
		Convey("Unknown Ingress IFID", func() {
			provider.EXPECT().SegmentsToRegister(gomock.Any(), proto.PathSegType_core).DoAndReturn(
				func(_, _ interface{}) (<-chan beacon.BeaconOrErr, error) {
					res := make(chan beacon.BeaconOrErr, 1)
					b := testBeaconOrErr(g, []common.IFIDType{graph.If_120_X_111_B})
					b.Beacon.InIfId = 10
					res <- b
					close(res)
					return res, nil
				})
			r.Run(context.Background())
		})
		Convey("Inactive Ingress IFID", func() {
			provider.EXPECT().SegmentsToRegister(gomock.Any(), proto.PathSegType_core).DoAndReturn(
				func(_, _ interface{}) (<-chan beacon.BeaconOrErr, error) {
					res := make(chan beacon.BeaconOrErr, 1)
					b := testBeaconOrErr(g, []common.IFIDType{graph.If_120_X_111_B})
					res <- b
					intfs.Get(b.Beacon.InIfId).Revoke(nil)
					close(res)
					return res, nil
				})
			r.Run(context.Background())
		})
		Convey("Invalid remote IFID", func() {
			provider.EXPECT().SegmentsToRegister(gomock.Any(), proto.PathSegType_core).DoAndReturn(
				func(_, _ interface{}) (<-chan beacon.BeaconOrErr, error) {
					res := make(chan beacon.BeaconOrErr, 1)
					b := testBeaconOrErr(g, []common.IFIDType{graph.If_120_X_111_B})
					intfs.Get(b.Beacon.InIfId).Activate(0)
					res <- b
					close(res)
					return res, nil
				})
			r.Run(context.Background())
		})
		Convey("Invalid peers are ignored", func() {
			provider.EXPECT().SegmentsToRegister(gomock.Any(), proto.PathSegType_core).DoAndReturn(
				func(_, _ interface{}) (<-chan beacon.BeaconOrErr, error) {
					res := make(chan beacon.BeaconOrErr, 1)
					res <- testBeaconOrErr(g, []common.IFIDType{graph.If_120_X_111_B})
					close(res)
					return res, nil
				},
			)
			for _, intf := range intfs.All() {
				intf.Activate(42)
			}
			intfs.Get(graph.If_111_C_121_X).Activate(0)
			var reg *path_mgmt.SegReg
			msgr.EXPECT().SendSegReg(gomock.Any(), gomock.Any(), gomock.Any(),
				gomock.Any()).Times(1).DoAndReturn(
				func(_, isegreg, iaddr, _ interface{}) error {
					reg = isegreg.(*path_mgmt.SegReg)
					return nil
				},
			)
			r.Run(context.Background())
			SoMsg("Len", len(reg.Recs), ShouldEqual, 1)
			asEntry := reg.Recs[0].Segment.ASEntries[reg.Recs[0].Segment.MaxAEIdx()]
			SoMsg("Entries", len(asEntry.HopEntries), ShouldEqual, 3)
			for _, entry := range asEntry.HopEntries {
				SoMsg("IA", entry.InIA(), ShouldNotResemble,
					xtest.MustParseIA("1-ff00:0:121"))
			}
		})
	})
}

func testBeaconOrErr(g *graph.Graph, desc []common.IFIDType) beacon.BeaconOrErr {
	b := testBeacon(g, desc)
	asEntry := b.Segment.ASEntries[b.Segment.MaxAEIdx()]
	return beacon.BeaconOrErr{
		Beacon: beacon.Beacon{
			InIfId:  asEntry.HopEntries[0].RemoteOutIF,
			Segment: b.Segment,
		},
	}
}

func testSigner(t *testing.T, priv common.RawBytes) infra.Signer {
	signer, err := trust.NewBasicSigner(priv, infra.SignerMeta{
		Src: ctrl.SignSrcDef{
			ChainVer: 42,
			TRCVer:   84,
			IA:       itopo.Get().ISD_AS,
		},
		Algo:    scrypto.Ed25519,
		ExpTime: time.Now().Add(time.Hour),
	})
	xtest.FailOnErr(t, err)
	return signer
}
