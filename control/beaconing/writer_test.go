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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"hash"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/control/beaconing/mock_beaconing"
	"github.com/scionproto/scion/control/ifstate"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/segment/seghandler"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
)

func TestRegistrarRun(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()

	testsLocal := []struct {
		name          string
		segType       seg.Type
		fn            string
		beacons       [][]uint16
		inactivePeers map[uint16]bool
	}{
		{
			name:    "Core segment",
			segType: seg.TypeCore,
			fn:      topoCore,
			beacons: [][]uint16{
				{graph.If_120_A_110_X},
				{graph.If_130_B_120_A, graph.If_120_A_110_X},
			},
		},
		{
			name:          "Up segment",
			segType:       seg.TypeUp,
			fn:            topoNonCore,
			inactivePeers: map[uint16]bool{graph.If_111_C_121_X: true},
			beacons: [][]uint16{
				{graph.If_120_X_111_B},
				{graph.If_130_B_120_A, graph.If_120_X_111_B},
			},
		},
	}
	for _, test := range testsLocal {
		t.Run(test.name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			topo, err := topology.FromJSONFile(test.fn)
			require.NoError(t, err)
			intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
			segProvider := mock_beaconing.NewMockSegmentProvider(mctrl)
			segStore := mock_beaconing.NewMockSegmentStore(mctrl)

			r := beaconing.WriteScheduler{
				Writer: &beaconing.LocalWriter{
					Extender: &beaconing.DefaultExtender{
						IA:  topo.IA(),
						MTU: topo.MTU(),
						SignerGen: testSignerGen{
							Signers: []trust.Signer{testSigner(t, priv, topo.IA())},
						},
						Intfs:      intfs,
						MAC:        macFactory,
						MaxExpTime: func() uint8 { return beacon.DefaultMaxExpTime },
						StaticInfo: func() *beaconing.StaticInfoCfg { return nil },
					},
					Intfs: intfs,
					Store: segStore,
					Type:  test.segType,
				},
				Intfs:    intfs,
				Tick:     beaconing.NewTick(time.Hour),
				Provider: segProvider,
				Type:     test.segType,
			}

			g := graph.NewDefaultGraph(mctrl)
			segProvider.EXPECT().SegmentsToRegister(gomock.Any(), test.segType).DoAndReturn(
				func(_, _ any) ([]beacon.Beacon, error) {
					res := make([]beacon.Beacon, 0, len(test.beacons))
					for _, desc := range test.beacons {
						res = append(res, testBeacon(g, desc))
					}
					return res, nil
				})

			var stored []*seg.Meta
			segStore.EXPECT().StoreSegs(gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, segs []*seg.Meta) (seghandler.SegStats, error) {
					stored = append(stored, segs...)
					var inserted []string
					for _, seg := range segs {
						inserted = append(inserted, seg.Segment.GetLoggingID())
					}
					return seghandler.SegStats{InsertedSegs: inserted}, nil
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
		beacons       [][]uint16
		inactivePeers map[uint16]bool
	}{
		{
			name:          "Down segment",
			segType:       seg.TypeDown,
			fn:            topoNonCore,
			inactivePeers: map[uint16]bool{graph.If_111_C_121_X: true},
			beacons: [][]uint16{
				{graph.If_120_X_111_B},
				{graph.If_130_B_120_A, graph.If_120_X_111_B},
			},
		},
	}
	for _, test := range testsRemote {
		t.Run(test.name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()

			topo, err := topology.FromJSONFile(test.fn)
			require.NoError(t, err)

			intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
			segProvider := mock_beaconing.NewMockSegmentProvider(mctrl)
			rpc := mock_beaconing.NewMockRPC(mctrl)

			r := beaconing.WriteScheduler{
				Writer: &beaconing.RemoteWriter{
					Extender: &beaconing.DefaultExtender{
						IA:  topo.IA(),
						MTU: topo.MTU(),
						SignerGen: testSignerGen{
							Signers: []trust.Signer{testSigner(t, priv, topo.IA())},
						},
						Intfs:      intfs,
						MAC:        macFactory,
						MaxExpTime: func() uint8 { return beacon.DefaultMaxExpTime },
						StaticInfo: func() *beaconing.StaticInfoCfg { return nil },
					},
					Pather: addrutil.Pather{
						NextHopper: topoWrap{Topo: topo},
					},
					RPC:   rpc,
					Type:  test.segType,
					Intfs: intfs,
				},
				Intfs:    intfs,
				Tick:     beaconing.NewTick(time.Hour),
				Provider: segProvider,
				Type:     test.segType,
			}

			g := graph.NewDefaultGraph(mctrl)
			segProvider.EXPECT().SegmentsToRegister(gomock.Any(), test.segType).DoAndReturn(
				func(_, _ any) ([]beacon.Beacon, error) {
					res := make([]beacon.Beacon, len(test.beacons))
					for _, desc := range test.beacons {
						res = append(res, testBeacon(g, desc))
					}
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
					scionPath, ok := s.Addr.Path.(snetpath.SCION)
					require.True(t, ok)
					if assert.NoError(t, path.DecodeFromBytes(scionPath.Raw)) {
						pathHopField := path.HopFields[0]

						segHopField := pseg.ASEntries[pseg.MaxIdx()].HopEntry.HopField
						assert.Equal(t, pathHopField.Mac, segHopField.MAC)
						assert.Equal(t, pathHopField.ConsIngress, segHopField.ConsIngress)
						assert.Equal(t, pathHopField.ConsEgress, segHopField.ConsEgress)

						nextHop := pathHopField.ConsIngress
						a := net.UDPAddrFromAddrPort(interfaceInfos(topo)[nextHop].InternalAddr)
						assert.Equal(t, a, s.Addr.NextHop)
					}
				})
			}
			// The second run should not do anything, since the period has not passed.
			r.Run(context.Background())
		})
	}

	t.Run("Faulty beacons are not sent", func(t *testing.T) {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()

		topo, err := topology.FromJSONFile(topoNonCore)
		require.NoError(t, err)
		intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
		segProvider := mock_beaconing.NewMockSegmentProvider(mctrl)
		rpc := mock_beaconing.NewMockRPC(mctrl)

		r := beaconing.WriteScheduler{
			Writer: &beaconing.RemoteWriter{
				Extender: &beaconing.DefaultExtender{
					IA:  topo.IA(),
					MTU: topo.MTU(),
					SignerGen: testSignerGen{
						Signers: []trust.Signer{testSigner(t, priv, topo.IA())},
					},
					Intfs:      intfs,
					MAC:        macFactory,
					MaxExpTime: func() uint8 { return beacon.DefaultMaxExpTime },
					StaticInfo: func() *beaconing.StaticInfoCfg { return nil },
				},
				Pather: addrutil.Pather{
					NextHopper: topoWrap{Topo: topo},
				},
				RPC:   rpc,
				Intfs: intfs,
				Type:  seg.TypeDown,
			},
			Intfs:    intfs,
			Tick:     beaconing.NewTick(time.Hour),
			Provider: segProvider,
			Type:     seg.TypeDown,
		}

		g := graph.NewDefaultGraph(mctrl)
		require.NoError(t, err)
		segProvider.EXPECT().SegmentsToRegister(gomock.Any(),
			seg.TypeDown).DoAndReturn(
			func(_, _ any) (<-chan beacon.Beacon, error) {
				res := make(chan beacon.Beacon, 1)
				b := testBeacon(g, []uint16{graph.If_120_X_111_B})
				b.InIfID = 10
				res <- b
				close(res)
				return res, nil
			})
		r.Run(context.Background())
	})
}

func testBeacon(g *graph.Graph, desc []uint16) beacon.Beacon {
	bseg := g.Beacon(desc)
	asEntry := bseg.ASEntries[bseg.MaxIdx()]
	bseg.ASEntries = bseg.ASEntries[:len(bseg.ASEntries)-1]

	return beacon.Beacon{
		InIfID:  asEntry.HopEntry.HopField.ConsIngress,
		Segment: bseg,
	}
}

func testSigner(t *testing.T, priv crypto.Signer, ia addr.IA) trust.Signer {
	return trust.Signer{
		PrivateKey: priv,
		Algorithm:  signed.ECDSAWithSHA256,
		IA:         ia,
		TRCID: cppki.TRCID{
			ISD:    ia.ISD(),
			Base:   1,
			Serial: 21,
		},
		SubjectKeyID: []byte("skid"),
		Expiration:   time.Now().Add(time.Hour),
	}
}

type testSignerGen struct {
	Signers []trust.Signer
}

func (s testSignerGen) Generate(ctx context.Context) ([]beaconing.Signer, error) {
	var signers []beaconing.Signer
	for _, s := range s.Signers {
		signers = append(signers, s)
	}
	return signers, nil
}

var macFactory = func() hash.Hash {
	mac, err := scrypto.InitMac(make([]byte, 16))
	// This can only happen if the library is messed up badly.
	if err != nil {
		panic(err)
	}
	return mac
}

type topoWrap struct {
	Topo topology.Topology
}

func (w topoWrap) UnderlayNextHop(id uint16) *net.UDPAddr {
	a, _ := w.Topo.UnderlayNextHop(iface.ID(id))
	return a
}

func interfaceInfos(topo topology.Topology) map[uint16]ifstate.InterfaceInfo {
	in := topo.IFInfoMap()
	result := make(map[uint16]ifstate.InterfaceInfo, len(in))
	for id, info := range in {
		result[uint16(id)] = ifstate.InterfaceInfo{
			ID:           uint16(info.ID),
			IA:           info.IA,
			LinkType:     info.LinkType,
			InternalAddr: netip.MustParseAddrPort(info.InternalAddr.String()),
			RemoteID:     uint16(info.RemoteIfID),
			MTU:          uint16(info.MTU),
		}
	}
	return result
}
