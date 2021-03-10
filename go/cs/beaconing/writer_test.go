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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"net"
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
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/pkg/trust"
)

func TestRegistrarRun(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()

	testsLocal := []struct {
		name          string
		segType       seg.Type
		fn            string
		beacons       [][]common.IFIDType
		inactivePeers map[common.IFIDType]bool
	}{
		{
			name:    "Core segment",
			segType: seg.TypeCore,
			fn:      topoCore,
			beacons: [][]common.IFIDType{
				{graph.If_120_A_110_X},
				{graph.If_130_B_120_A, graph.If_120_A_110_X},
			},
		},
		{
			name:          "Up segment",
			segType:       seg.TypeUp,
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
			intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
			segProvider := mock_beaconing.NewMockSegmentProvider(mctrl)
			segStore := mock_beaconing.NewMockSegmentStore(mctrl)

			r := WriteScheduler{
				Writer: &LocalWriter{
					Extender: &DefaultExtender{
						IA:         topoProvider.Get().IA(),
						MTU:        topoProvider.Get().MTU(),
						Signer:     testSigner(t, priv, topoProvider.Get().IA()),
						Intfs:      intfs,
						MAC:        macFactory,
						MaxExpTime: func() uint8 { return uint8(beacon.DefaultMaxExpTime) },
						StaticInfo: func() *StaticInfoCfg { return nil },
					},
					Intfs: intfs,
					Store: segStore,
					Type:  test.segType,
				},
				Intfs:    intfs,
				Tick:     NewTick(time.Hour),
				Provider: segProvider,
				Type:     test.segType,
			}
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
			var stored []*seg.Meta
			segStore.EXPECT().StoreSegs(gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, segs []*seg.Meta) (seghandler.SegStats, error) {
					for _, s := range segs {
						stored = append(stored, s)
					}
					return seghandler.SegStats{}, nil
				},
			)

			r.Run(context.Background())
			assert.Len(t, stored, len(test.beacons))
			for _, s := range stored {
				assert.NoError(t, s.Segment.Validate(seg.ValidateSegment))
				assert.NoError(t, s.Segment.VerifyASEntry(context.Background(),
					segVerifier{pubKey: pub}, s.Segment.MaxIdx()))
				assert.Equal(t, test.segType, s.Type)
			}
			// The second run should not do anything, since the period has not passed.
			r.Run(context.Background())
		})
	}
	testsRemote := []struct {
		name          string
		segType       seg.Type
		fn            string
		beacons       [][]common.IFIDType
		inactivePeers map[common.IFIDType]bool
	}{
		{
			name:          "Down segment",
			segType:       seg.TypeDown,
			fn:            topoNonCore,
			inactivePeers: map[common.IFIDType]bool{graph.If_111_C_121_X: true},
			beacons: [][]common.IFIDType{
				{graph.If_120_X_111_B},
				{graph.If_130_B_120_A, graph.If_120_X_111_B},
			},
		},
	}
	for _, test := range testsRemote {
		t.Run(test.name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			topoProvider := itopotest.TopoProviderFromFile(t, test.fn)
			intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
			segProvider := mock_beaconing.NewMockSegmentProvider(mctrl)
			rpc := mock_beaconing.NewMockRPC(mctrl)

			r := WriteScheduler{
				Writer: &RemoteWriter{
					Extender: &DefaultExtender{
						IA:         topoProvider.Get().IA(),
						MTU:        topoProvider.Get().MTU(),
						Signer:     testSigner(t, priv, topoProvider.Get().IA()),
						Intfs:      intfs,
						MAC:        macFactory,
						MaxExpTime: func() uint8 { return uint8(beacon.DefaultMaxExpTime) },
						StaticInfo: func() *StaticInfoCfg { return nil },
					},
					Pather: addrutil.Pather{
						UnderlayNextHop: func(ifID uint16) (*net.UDPAddr, bool) {
							return topoProvider.Get().UnderlayNextHop2(common.IFIDType(ifID))
						},
					},
					RPC:   rpc,
					Type:  test.segType,
					Intfs: intfs,
				},
				Intfs:    intfs,
				Tick:     NewTick(time.Hour),
				Provider: segProvider,
				Type:     test.segType,
			}
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
				Meta seg.Meta
				Addr *snet.SVCAddr
			}
			segMu := sync.Mutex{}
			var sent []regMsg
			// Collect the segments that are sent on the messenger.

			rpc.EXPECT().RegisterSegment(gomock.Any(), gomock.Any(),
				gomock.Any()).Times(len(test.beacons)).DoAndReturn(
				func(_ context.Context, meta seg.Meta, remote net.Addr) error {
					segMu.Lock()
					defer segMu.Unlock()
					sent = append(sent, regMsg{
						Meta: meta,
						Addr: remote.(*snet.SVCAddr),
					})
					return nil
				},
			)
			r.Run(context.Background())
			require.Len(t, sent, len(test.beacons))
			for segIdx, s := range sent {
				t.Run(fmt.Sprintf("seg idx %d", segIdx), func(t *testing.T) {
					pseg := s.Meta.Segment

					assert.NoError(t, pseg.Validate(seg.ValidateSegment))
					assert.NoError(t, pseg.VerifyASEntry(context.Background(),
						segVerifier{pubKey: pub}, pseg.MaxIdx()))

					assert.Equal(t, pseg.FirstIA(), s.Addr.IA)
					assert.Equal(t, addr.SvcCS, s.Addr.SVC)

					var path scion.Decoded
					if assert.NoError(t, path.DecodeFromBytes(s.Addr.Path.Raw)) {
						pathHopField := path.HopFields[0]

						segHopField := pseg.ASEntries[pseg.MaxIdx()].HopEntry.HopField
						assert.Equal(t, []byte(pathHopField.Mac), segHopField.MAC)
						assert.Equal(t, pathHopField.ConsIngress, segHopField.ConsIngress)
						assert.Equal(t, pathHopField.ConsEgress, segHopField.ConsEgress)

						nextHop := common.IFIDType(pathHopField.ConsIngress)
						a := topoProvider.Get().IFInfoMap()[nextHop].InternalAddr
						assert.Equal(t, a, s.Addr.NextHop)
					}
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
		intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
		segProvider := mock_beaconing.NewMockSegmentProvider(mctrl)

		r := WriteScheduler{
			Writer: &LocalWriter{
				Extender: &DefaultExtender{
					IA:         topoProvider.Get().IA(),
					MTU:        topoProvider.Get().MTU(),
					Signer:     testSigner(t, priv, topoProvider.Get().IA()),
					Intfs:      intfs,
					MAC:        macFactory,
					MaxExpTime: func() uint8 { return uint8(beacon.DefaultMaxExpTime) },
					StaticInfo: func() *StaticInfoCfg { return nil },
				},
				Intfs: intfs,
				Type:  seg.TypeCore,
			},
			Intfs:    intfs,
			Tick:     NewTick(time.Hour),
			Provider: segProvider,
			Type:     seg.TypeCore,
		}
		res := make(chan beacon.BeaconOrErr, 3)
		segProvider.EXPECT().SegmentsToRegister(gomock.Any(), seg.TypeCore).DoAndReturn(
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
		intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
		segProvider := mock_beaconing.NewMockSegmentProvider(mctrl)
		rpc := mock_beaconing.NewMockRPC(mctrl)

		r := WriteScheduler{
			Writer: &RemoteWriter{
				Extender: &DefaultExtender{
					IA:         topoProvider.Get().IA(),
					MTU:        topoProvider.Get().MTU(),
					Signer:     testSigner(t, priv, topoProvider.Get().IA()),
					Intfs:      intfs,
					MAC:        macFactory,
					MaxExpTime: func() uint8 { return uint8(beacon.DefaultMaxExpTime) },
					StaticInfo: func() *StaticInfoCfg { return nil },
				},
				Pather: addrutil.Pather{
					UnderlayNextHop: func(ifID uint16) (*net.UDPAddr, bool) {
						return topoProvider.Get().UnderlayNextHop2(common.IFIDType(ifID))
					},
				},
				RPC:   rpc,
				Intfs: intfs,
				Type:  seg.TypeDown,
			},
			Intfs:    intfs,
			Tick:     NewTick(time.Hour),
			Provider: segProvider,
			Type:     seg.TypeDown,
		}
		g := graph.NewDefaultGraph(mctrl)
		require.NoError(t, err)
		segProvider.EXPECT().SegmentsToRegister(gomock.Any(),
			seg.TypeDown).DoAndReturn(
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
	bseg := g.Beacon(desc)
	asEntry := bseg.ASEntries[bseg.MaxIdx()]
	bseg.ASEntries = bseg.ASEntries[:len(bseg.ASEntries)-1]

	return beacon.BeaconOrErr{
		Beacon: beacon.Beacon{
			InIfId:  common.IFIDType(asEntry.HopEntry.HopField.ConsIngress),
			Segment: bseg,
		},
	}
}

func testSigner(t *testing.T, priv crypto.Signer, ia addr.IA) seg.Signer {
	return trust.Signer{
		PrivateKey: priv,
		Algorithm:  signed.ECDSAWithSHA256,
		IA:         ia,
		TRCID: cppki.TRCID{
			ISD:    ia.I,
			Base:   1,
			Serial: 21,
		},
		SubjectKeyID: []byte("skid"),
		Expiration:   time.Now().Add(time.Hour),
	}
}

var macFactory = func() hash.Hash {
	mac, err := scrypto.InitMac(make([]byte, 16))
	// This can only happen if the library is messed up badly.
	if err != nil {
		panic(err)
	}
	return mac
}
