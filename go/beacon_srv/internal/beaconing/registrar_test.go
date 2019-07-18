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
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
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
			topoProvider := xtest.TopoProviderFromFile(t, test.fn)
			segProvider := mock_beaconing.NewMockSegmentProvider(mctrl)
			msgr := mock_infra.NewMockMessenger(mctrl)
			cfg := RegistrarConf{
				Config: ExtenderConf{
					Signer: testSigner(t, priv, topoProvider.Get().ISD_AS),
					Mac:    mac,
					Intfs:  ifstate.NewInterfaces(topoProvider.Get().IFInfoMap, ifstate.Config{}),
					MTU:    uint16(topoProvider.Get().MTU),
				},
				Period:       time.Hour,
				Msgr:         msgr,
				SegProvider:  segProvider,
				TopoProvider: topoProvider,
				SegType:      test.segType,
			}
			r, err := cfg.New()
			SoMsg("err", err, ShouldBeNil)
			g := graph.NewDefaultGraph(mctrl)
			segProvider.EXPECT().SegmentsToRegister(gomock.Any(), test.segType).DoAndReturn(
				func(_, _ interface{}) (<-chan beacon.BeaconOrErr, error) {
					res := make(chan beacon.BeaconOrErr, len(test.beacons))
					for _, desc := range test.beacons {
						res <- testBeaconOrErr(g, desc)
					}
					close(res)
					return res, nil
				})
			type regMsg struct {
				Reg  *path_mgmt.SegReg
				Addr *snet.Addr
			}
			segMu := sync.Mutex{}
			var sent []regMsg
			// Collect the segments that are sent on the messenger.
			msgr.EXPECT().SendSegReg(gomock.Any(), gomock.Any(), gomock.Any(),
				gomock.Any()).Times(len(test.beacons)).DoAndReturn(
				func(_, isegreg, iaddr, _ interface{}) error {
					segMu.Lock()
					defer segMu.Unlock()
					sent = append(sent, regMsg{
						Reg:  isegreg.(*path_mgmt.SegReg),
						Addr: iaddr.(*snet.Addr),
					})
					return nil
				},
			)
			for ifid, intf := range cfg.Config.Intfs.All() {
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
				Convey(fmt.Sprintf("Segment %d can be validated", segIdx), func() {
					err := pseg.Validate(seg.ValidateSegment)
					SoMsg("err", err, ShouldBeNil)
				})
				Convey(fmt.Sprintf("Segment %d is verifiable", segIdx), func() {
					err := pseg.VerifyASEntry(context.Background(),
						segVerifier(pub), pseg.MaxAEIdx())
					SoMsg("err", err, ShouldBeNil)
				})
				Convey(fmt.Sprintf("Segment %d is sent to the PS", segIdx), func() {
					if !test.remotePS {
						SoMsg("IA", s.Addr.IA, ShouldResemble, topoProvider.Get().ISD_AS)
						a := addr.NewSVCUDPAppAddr(addr.SvcPS)
						SoMsg("Host", s.Addr.Host, ShouldResemble, a)
						return
					}
					SoMsg("IA", s.Addr.IA, ShouldResemble, pseg.FirstIA())
					SoMsg("Host", s.Addr.Host.L3, ShouldResemble, addr.SvcPS)
					hopF, err := s.Addr.Path.GetHopField(s.Addr.Path.HopOff)
					SoMsg("err", err, ShouldBeNil)
					SoMsg("HopField", []uint8(hopF.Pack()), ShouldResemble,
						pseg.ASEntries[pseg.MaxAEIdx()].HopEntries[0].RawHopField)
					a := topoProvider.Get().IFInfoMap[hopF.ConsIngress].InternalAddrs
					SoMsg("Next", s.Addr.NextHop, ShouldResemble, a.PublicOverlay(a.Overlay))
				})
			}
			// The second run should not do anything, since the period has not passed.
			r.Run(context.Background())
		})
	}
	Convey("Run drains the channel", t, func() {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		topoProvider := xtest.TopoProviderFromFile(t, topoCore)
		segProvider := mock_beaconing.NewMockSegmentProvider(mctrl)
		msgr := mock_infra.NewMockMessenger(mctrl)
		cfg := RegistrarConf{
			Config: ExtenderConf{
				Signer: testSigner(t, priv, topoProvider.Get().ISD_AS),
				Mac:    mac,
				Intfs:  ifstate.NewInterfaces(topoProvider.Get().IFInfoMap, ifstate.Config{}),
				MTU:    uint16(topoProvider.Get().MTU),
			},
			Msgr:         msgr,
			SegProvider:  segProvider,
			TopoProvider: topoProvider,
			SegType:      proto.PathSegType_core,
		}
		r, err := cfg.New()
		SoMsg("err", err, ShouldBeNil)
		res := make(chan beacon.BeaconOrErr, 3)
		segProvider.EXPECT().SegmentsToRegister(gomock.Any(), proto.PathSegType_core).DoAndReturn(
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
		topoProvider := xtest.TopoProviderFromFile(t, topoNonCore)
		segProvider := mock_beaconing.NewMockSegmentProvider(mctrl)
		msgr := mock_infra.NewMockMessenger(mctrl)
		cfg := RegistrarConf{
			Config: ExtenderConf{
				Signer: testSigner(t, priv, topoProvider.Get().ISD_AS),
				Mac:    mac,
				Intfs:  ifstate.NewInterfaces(topoProvider.Get().IFInfoMap, ifstate.Config{}),
				MTU:    uint16(topoProvider.Get().MTU),
			},
			Msgr:         msgr,
			SegProvider:  segProvider,
			TopoProvider: topoProvider,
			SegType:      proto.PathSegType_core,
		}
		r, err := cfg.New()
		SoMsg("err", err, ShouldBeNil)
		g := graph.NewDefaultGraph(mctrl)
		SoMsg("err", err, ShouldBeNil)
		Convey("Unknown Ingress IFID", func() {
			segProvider.EXPECT().SegmentsToRegister(gomock.Any(),
				proto.PathSegType_core).DoAndReturn(
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

func testSigner(t *testing.T, priv common.RawBytes, ia addr.IA) infra.Signer {
	signer, err := trust.NewBasicSigner(priv, infra.SignerMeta{
		Src: ctrl.SignSrcDef{
			ChainVer: 42,
			TRCVer:   84,
			IA:       ia,
		},
		Algo:    scrypto.Ed25519,
		ExpTime: time.Now().Add(time.Hour),
	})
	xtest.FailOnErr(t, err)
	return signer
}
