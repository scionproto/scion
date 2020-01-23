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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beaconing/mock_beaconing"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/mock_infra"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/proto"
)

func TestRegistrarRun(t *testing.T) {
	mac, err := scrypto.InitMac(make(common.RawBytes, 16))
	require.NoError(t, err)
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	require.NoError(t, err)

	testsLocal := []struct {
		name          string
		segType       proto.PathSegType
		fn            string
		beacons       [][]common.IFIDType
		inactivePeers map[common.IFIDType]bool
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
	}
	for _, test := range testsLocal {
		t.Run(test.name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			topoProvider := itopotest.TopoProviderFromFile(t, test.fn)
			segProvider := mock_beaconing.NewMockSegmentProvider(mctrl)
			segStore := mock_beaconing.NewMockSegmentStore(mctrl)
			cfg := RegistrarConf{
				Config: ExtenderConf{
					Signer: testSigner(t, priv, topoProvider.Get().IA()),
					Mac:    mac,
					Intfs: ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(),
						ifstate.Config{}),
					MTU:           topoProvider.Get().MTU(),
					GetMaxExpTime: maxExpTimeFactory(beacon.DefaultMaxExpTime),
				},
				Period:       time.Hour,
				SegProvider:  segProvider,
				SegStore:     segStore,
				TopoProvider: topoProvider,
				SegType:      test.segType,
			}
			r, err := cfg.New()
			require.NoError(t, err)
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
			var stored []seg.Meta
			segStore.EXPECT().StoreSegs(gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, segs []*seghandler.SegWithHP) (seghandler.SegStats, error) {
					for _, s := range segs {
						stored = append(stored, seg.Meta{Type: s.Seg.Type, Segment: s.Seg.Segment})
					}
					return seghandler.SegStats{}, nil
				},
			)

			for ifid, intf := range cfg.Config.Intfs.All() {
				if test.inactivePeers[ifid] {
					continue
				}
				intf.Activate(42)
			}
			r.Run(context.Background())
			assert.Len(t, stored, len(test.beacons))
			for _, s := range stored {
				assert.NoError(t, s.Segment.Validate(seg.ValidateSegment))
				assert.NoError(t, s.Segment.VerifyASEntry(context.Background(),
					segVerifier(pub), s.Segment.MaxAEIdx()))
				assert.Equal(t, test.segType, s.Type)
			}
			// The second run should not do anything, since the period has not passed.
			r.Run(context.Background())
		})
	}
	testsRemote := []struct {
		name          string
		segType       proto.PathSegType
		fn            string
		beacons       [][]common.IFIDType
		inactivePeers map[common.IFIDType]bool
		remotePS      bool
	}{
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
	for _, test := range testsRemote {
		t.Run(test.name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			topoProvider := itopotest.TopoProviderFromFile(t, test.fn)
			segProvider := mock_beaconing.NewMockSegmentProvider(mctrl)
			msgr := mock_infra.NewMockMessenger(mctrl)
			cfg := RegistrarConf{
				Config: ExtenderConf{
					Signer: testSigner(t, priv, topoProvider.Get().IA()),
					Mac:    mac,
					Intfs: ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(),
						ifstate.Config{}),
					MTU:           topoProvider.Get().MTU(),
					GetMaxExpTime: maxExpTimeFactory(beacon.DefaultMaxExpTime),
				},
				Period:       time.Hour,
				Msgr:         msgr,
				SegProvider:  segProvider,
				TopoProvider: topoProvider,
				SegType:      test.segType,
			}
			r, err := cfg.New()
			require.NoError(t, err)
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
				Addr *snet.SVCAddr
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
						Addr: iaddr.(*snet.SVCAddr),
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
			require.Len(t, sent, len(test.beacons))
			for segIdx, s := range sent {
				t.Run(fmt.Sprintf("seg idx %d", segIdx), func(t *testing.T) {
					require.Len(t, s.Reg.Recs, 1)
					pseg := s.Reg.Recs[0].Segment

					assert.NoError(t, pseg.Validate(seg.ValidateSegment))
					assert.NoError(t, pseg.VerifyASEntry(context.Background(),
						segVerifier(pub), pseg.MaxAEIdx()))

					if !test.remotePS {
						assert.Equal(t, topoProvider.Get().IA(), s.Addr.IA)
						assert.Equal(t, addr.SvcPS, s.Addr.SVC)
						return
					}
					assert.Equal(t, pseg.FirstIA(), s.Addr.IA)
					assert.Equal(t, addr.SvcPS, s.Addr.SVC)
					hopF, err := s.Addr.Path.GetHopField(s.Addr.Path.HopOff)
					require.NoError(t, err)
					assert.Equal(t, []uint8(hopF.Pack()),
						pseg.ASEntries[pseg.MaxAEIdx()].HopEntries[0].RawHopField)
					a := topoProvider.Get().IFInfoMap()[hopF.ConsIngress].InternalAddr
					assert.Equal(t, a, s.Addr.NextHop)
				})
			}
			// The second run should not do anything, since the period has not passed.
			r.Run(context.Background())
		})
	}
	t.Run("Run drains the channel", func(t *testing.T) {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		topoProvider := itopotest.TopoProviderFromFile(t, topoCore)
		segProvider := mock_beaconing.NewMockSegmentProvider(mctrl)
		msgr := mock_infra.NewMockMessenger(mctrl)
		cfg := RegistrarConf{
			Config: ExtenderConf{
				Signer: testSigner(t, priv, topoProvider.Get().IA()),
				Mac:    mac,
				Intfs: ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(),
					ifstate.Config{}),
				MTU:           topoProvider.Get().MTU(),
				GetMaxExpTime: maxExpTimeFactory(beacon.DefaultMaxExpTime),
			},
			Msgr:         msgr,
			SegProvider:  segProvider,
			TopoProvider: topoProvider,
			SegType:      proto.PathSegType_core,
		}
		r, err := cfg.New()
		require.NoError(t, err)
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
			assert.Zero(t, b)
		default:
			t.Fatal("Must not block")
		}
	})
	t.Run("Faulty beacons are not sent", func(t *testing.T) {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		topoProvider := itopotest.TopoProviderFromFile(t, topoNonCore)
		segProvider := mock_beaconing.NewMockSegmentProvider(mctrl)
		msgr := mock_infra.NewMockMessenger(mctrl)
		cfg := RegistrarConf{
			Config: ExtenderConf{
				Signer: testSigner(t, priv, topoProvider.Get().IA()),
				Mac:    mac,
				Intfs: ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(),
					ifstate.Config{}),
				MTU:           topoProvider.Get().MTU(),
				GetMaxExpTime: maxExpTimeFactory(beacon.DefaultMaxExpTime),
			},
			Msgr:         msgr,
			SegProvider:  segProvider,
			TopoProvider: topoProvider,
			SegType:      proto.PathSegType_down,
		}
		r, err := cfg.New()
		require.NoError(t, err)
		g := graph.NewDefaultGraph(mctrl)
		require.NoError(t, err)
		segProvider.EXPECT().SegmentsToRegister(gomock.Any(),
			proto.PathSegType_down).DoAndReturn(
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
	signer, err := trust.NewSigner(
		trust.SignerConf{
			ChainVer: 42,
			TRCVer:   84,
			Validity: scrypto.Validity{NotAfter: util.UnixTime{Time: time.Now().Add(time.Hour)}},
			Key: keyconf.Key{
				Type:      keyconf.PrivateKey,
				Algorithm: scrypto.Ed25519,
				Bytes:     priv,
				ID:        keyconf.ID{IA: ia},
			},
		},
	)
	require.NoError(t, err)
	return signer
}
