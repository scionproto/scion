// Copyright 2020 Anapaya Systems
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

package hiddenpath_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"hash"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beaconing"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	"github.com/scionproto/scion/go/pkg/hiddenpath/mock_hiddenpath"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	"github.com/scionproto/scion/go/pkg/trust"
)

const topoNonCore = "testdata/topology.json"

func TestRemoteBeaconWriterWrite(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()

	validatePublicSeg := func(t *testing.T, pseg *seg.PathSegment,
		a *snet.SVCAddr, topoProvider topology.Provider) {

		assert.NoError(t, pseg.Validate(seg.ValidateSegment))
		assert.NoError(t, pseg.VerifyASEntry(context.Background(),
			segVerifier{pubKey: pub}, pseg.MaxIdx()))

		assert.Equal(t, pseg.FirstIA(), a.IA)
		assert.Equal(t, addr.SvcCS, a.SVC)

		var path scion.Decoded
		if assert.NoError(t, path.DecodeFromBytes(a.Path.Raw)) {
			pathHopField := path.HopFields[0]

			segHopField := pseg.ASEntries[pseg.MaxIdx()].HopEntry.HopField
			assert.Equal(t, []byte(pathHopField.Mac), segHopField.MAC)
			assert.Equal(t, pathHopField.ConsIngress, segHopField.ConsIngress)
			assert.Equal(t, pathHopField.ConsEgress, segHopField.ConsEgress)

			nextHop := common.IFIDType(pathHopField.ConsIngress)
			ta := topoProvider.Get().IFInfoMap()[nextHop].InternalAddr
			assert.Equal(t, ta, a.NextHop)
		}
	}
	validateHS := func(t *testing.T, pseg *seg.PathSegment) {
		assert.NoError(t, pseg.Validate(seg.ValidateSegment))
		assert.NoError(t, pseg.VerifyASEntry(context.Background(),
			segVerifier{pubKey: pub}, pseg.MaxIdx()))
	}
	topoProvider := itopotest.TopoProviderFromFile(t, topoNonCore)

	testCases := map[string]struct {
		beacons   [][]common.IFIDType
		createRPC func(*testing.T, *gomock.Controller) hiddenpath.Register
		policy    hiddenpath.RegistrationPolicy
		resolver  func(*gomock.Controller) hiddenpath.AddressResolver
	}{
		"Only public registration": {
			beacons: [][]common.IFIDType{
				{graph.If_120_X_111_B},
				{graph.If_130_B_120_A, graph.If_120_X_111_B},
			},
			createRPC: func(t *testing.T,
				ctrl *gomock.Controller) hiddenpath.Register {

				rpc := mock_hiddenpath.NewMockRegister(ctrl)
				rpc.EXPECT().RegisterSegment(gomock.Any(), gomock.Any(),
					matchSVCCS("1-ff00:0:120")).DoAndReturn(
					func(_ context.Context, reg hiddenpath.SegmentRegistration,
						remote net.Addr) error {
						validatePublicSeg(t, reg.Seg.Segment, remote.(*snet.SVCAddr), topoProvider)
						return nil
					},
				)
				rpc.EXPECT().RegisterSegment(gomock.Any(), gomock.Any(),
					matchSVCCS("1-ff00:0:130")).DoAndReturn(
					func(_ context.Context, reg hiddenpath.SegmentRegistration,
						remote net.Addr) error {
						validatePublicSeg(t, reg.Seg.Segment, remote.(*snet.SVCAddr), topoProvider)
						return nil
					},
				)

				return rpc
			},
			policy: hiddenpath.RegistrationPolicy{
				uint64(graph.If_111_B_120_X): hiddenpath.InterfacePolicy{
					Public: true,
				},
			},
			resolver: func(ctrl *gomock.Controller) hiddenpath.AddressResolver {
				return mock_hiddenpath.NewMockAddressResolver(ctrl)
			},
		},
		"single interface hidden": {
			beacons: [][]common.IFIDType{
				{graph.If_120_X_111_B},
				{graph.If_130_B_120_A, graph.If_120_X_111_B},
			},
			createRPC: func(t *testing.T,
				ctrl *gomock.Controller) hiddenpath.Register {
				rpc := mock_hiddenpath.NewMockRegister(ctrl)
				rpc.EXPECT().RegisterSegment(gomock.Any(), gomock.Any(),
					addrMatcher{udp: &snet.UDPAddr{
						IA:   xtest.MustParseIA("1-ff00:0:114"),
						Host: xtest.MustParseUDPAddr(t, "10.1.0.1:404"),
					}}).Times(2).DoAndReturn(
					func(_ context.Context, reg hiddenpath.SegmentRegistration,
						remote net.Addr) error {
						validateHS(t, reg.Seg.Segment)
						return nil
					},
				)
				return rpc
			},
			policy: hiddenpath.RegistrationPolicy{
				uint64(graph.If_111_B_120_X): hiddenpath.InterfacePolicy{
					Groups: map[hiddenpath.GroupID]*hiddenpath.Group{
						mustParseGroupID(t, "ff00:0:140-2"): {
							ID: mustParseGroupID(t, "ff00:0:140-2"),
							Registries: map[addr.IA]struct{}{
								xtest.MustParseIA("1-ff00:0:114"): {},
							},
							Writers: map[addr.IA]struct{}{xtest.MustParseIA("1-ff00:0:111"): {}},
						},
					},
				},
			},
			resolver: func(ctrl *gomock.Controller) hiddenpath.AddressResolver {
				resolver := mock_hiddenpath.NewMockAddressResolver(ctrl)
				resolver.EXPECT().Resolve(gomock.Any(), xtest.MustParseIA("1-ff00:0:114")).
					Times(2).Return(
					&snet.UDPAddr{
						IA:   xtest.MustParseIA("1-ff00:0:114"),
						Host: xtest.MustParseUDPAddr(t, "10.1.0.1:404"),
					}, nil)
				return resolver
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})

			w := &hiddenpath.BeaconWriter{
				Intfs: intfs,
				Extender: &beaconing.DefaultExtender{
					IA:         topoProvider.Get().IA(),
					MTU:        topoProvider.Get().MTU(),
					Signer:     testSigner(t, priv, topoProvider.Get().IA()),
					Intfs:      intfs,
					MAC:        macFactory,
					MaxExpTime: func() uint8 { return uint8(beacon.DefaultMaxExpTime) },
					StaticInfo: func() *beaconing.StaticInfoCfg { return nil },
				},
				RPC: tc.createRPC(t, ctrl),
				Pather: addrutil.Pather{
					UnderlayNextHop: func(ifID uint16) (*net.UDPAddr, bool) {
						return topoProvider.Get().UnderlayNextHop2(common.IFIDType(ifID))
					},
				},
				RegistrationPolicy: tc.policy,
				AddressResolver:    tc.resolver(ctrl),
			}
			g := graph.NewDefaultGraph(ctrl)
			beacons := make(chan beacon.BeaconOrErr, len(tc.beacons))
			for _, desc := range tc.beacons {
				beacons <- testBeaconOrErr(g, desc)
			}
			close(beacons)
			// Collect the segments that are sent on the messenger.

			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			w.Write(ctx, beacons, sortedIntfs(intfs, topology.Peer))
		})
	}
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

type segVerifier struct {
	pubKey crypto.PublicKey
}

func (v segVerifier) Verify(_ context.Context, signedMsg *cryptopb.SignedMessage,
	associatedData ...[]byte) (*signed.Message, error) {

	return signed.Verify(signedMsg, v.pubKey, associatedData...)
}

// sortedIntfs returns all interfaces of the given link type sorted by interface
// ID.
func sortedIntfs(intfs *ifstate.Interfaces, linkType topology.LinkType) []common.IFIDType {

	var result []common.IFIDType
	for ifid, intf := range intfs.All() {
		topoInfo := intf.TopoInfo()
		if topoInfo.LinkType != linkType {
			continue
		}
		result = append(result, ifid)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func matchSVCCS(ia string) gomock.Matcher {
	return addrMatcher{
		svc: &snet.SVCAddr{
			IA:  xtest.MustParseIA(ia),
			SVC: addr.SvcCS,
		},
	}
}

type addrMatcher struct {
	svc *snet.SVCAddr
	udp *snet.UDPAddr
}

func (m addrMatcher) Matches(other interface{}) bool {
	if m.svc != nil {
		svc, ok := other.(*snet.SVCAddr)
		if !ok {
			return false
		}
		if !m.svc.IA.Equal(svc.IA) {
			return false
		}
		if !m.svc.SVC.Equal(svc.SVC) {
			return false
		}
		return true
	}
	if m.udp != nil {
		udp, ok := other.(*snet.UDPAddr)
		if !ok {
			return false
		}
		if !m.udp.IA.Equal(udp.IA) {
			return false
		}
		if !equalAddr(m.udp.Host, udp.Host) {
			return false
		}
		return true
	}
	return false
}

func (m addrMatcher) String() string {
	if m.svc != nil {
		return m.svc.String()
	}
	if m.udp != nil {
		return m.udp.String()
	}
	return ""
}

func equalAddr(a, b *net.UDPAddr) bool {
	return a.Port == b.Port && a.IP.Equal(b.IP) && a.Zone == b.Zone
}
