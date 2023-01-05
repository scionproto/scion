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
	"inet.af/netaddr"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/control/ifstate"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath"
	"github.com/scionproto/scion/pkg/experimental/hiddenpath/mock_hiddenpath"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
)

const topoNonCore = "testdata/topology.json"

func TestRemoteBeaconWriterWrite(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()

	validatePublicSeg := func(t *testing.T, pseg *seg.PathSegment,
		a *snet.SVCAddr, topo topology.Topology) {

		assert.NoError(t, pseg.Validate(seg.ValidateSegment))
		assert.NoError(t, pseg.VerifyASEntry(context.Background(),
			segVerifier{pubKey: pub}, pseg.MaxIdx()))

		assert.Equal(t, pseg.FirstIA(), a.IA)
		assert.Equal(t, addr.SvcCS, a.SVC)

		var path scion.Decoded
		scionPath, ok := a.Path.(snetpath.SCION)
		require.True(t, ok)
		if assert.NoError(t, path.DecodeFromBytes(scionPath.Raw)) {
			pathHopField := path.HopFields[0]

			segHopField := pseg.ASEntries[pseg.MaxIdx()].HopEntry.HopField
			assert.Equal(t, pathHopField.Mac, segHopField.MAC)
			assert.Equal(t, pathHopField.ConsIngress, segHopField.ConsIngress)
			assert.Equal(t, pathHopField.ConsEgress, segHopField.ConsEgress)

			nextHop := pathHopField.ConsIngress
			ta := interfaceInfos(topo)[nextHop].InternalAddr.UDPAddr()
			assert.Equal(t, ta, a.NextHop)
		}
	}
	validateHS := func(t *testing.T, pseg *seg.PathSegment) {
		assert.NoError(t, pseg.Validate(seg.ValidateSegment))
		assert.NoError(t, pseg.VerifyASEntry(context.Background(),
			segVerifier{pubKey: pub}, pseg.MaxIdx()))
	}
	topo, err := topology.FromJSONFile(topoNonCore)
	require.NoError(t, err)

	testCases := map[string]struct {
		beacons   [][]uint16
		createRPC func(*testing.T, *gomock.Controller) hiddenpath.Register
		policy    hiddenpath.RegistrationPolicy
		resolver  func(*gomock.Controller) hiddenpath.AddressResolver
	}{
		"Only public registration": {
			beacons: [][]uint16{
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
						validatePublicSeg(t, reg.Seg.Segment, remote.(*snet.SVCAddr), topo)
						return nil
					},
				)
				rpc.EXPECT().RegisterSegment(gomock.Any(), gomock.Any(),
					matchSVCCS("1-ff00:0:130")).DoAndReturn(
					func(_ context.Context, reg hiddenpath.SegmentRegistration,
						remote net.Addr) error {
						validatePublicSeg(t, reg.Seg.Segment, remote.(*snet.SVCAddr), topo)
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
			beacons: [][]uint16{
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
					func(_ context.Context, reg hiddenpath.SegmentRegistration, _ net.Addr) error {
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
			intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})

			w := &hiddenpath.BeaconWriter{
				Intfs: intfs,
				Extender: &beaconing.DefaultExtender{
					IA:         topo.IA(),
					MTU:        topo.MTU(),
					Signer:     testSigner(t, priv, topo.IA()),
					Intfs:      intfs,
					MAC:        macFactory,
					MaxExpTime: func() uint8 { return beacon.DefaultMaxExpTime },
					StaticInfo: func() *beaconing.StaticInfoCfg { return nil },
				},
				RPC: tc.createRPC(t, ctrl),
				Pather: addrutil.Pather{
					NextHopper: topoWrap{Topo: topo},
				},
				RegistrationPolicy: tc.policy,
				AddressResolver:    tc.resolver(ctrl),
			}
			g := graph.NewDefaultGraph(ctrl)
			var beacons []beacon.Beacon
			for _, desc := range tc.beacons {
				beacons = append(beacons, testBeacon(g, desc))
			}

			ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
			defer cancelF()

			stats, err := w.Write(ctx, beacons, sortedIntfs(intfs, topology.Peer))
			assert.NoError(t, err)
			assert.Equal(t, len(beacons), stats.Count)
		})
	}
}

func testBeacon(g *graph.Graph, desc []uint16) beacon.Beacon {
	bseg := g.Beacon(desc)
	asEntry := bseg.ASEntries[bseg.MaxIdx()]
	bseg.ASEntries = bseg.ASEntries[:len(bseg.ASEntries)-1]

	return beacon.Beacon{
		InIfId:  asEntry.HopEntry.HopField.ConsIngress,
		Segment: bseg,
	}
}

func testSigner(t *testing.T, priv crypto.Signer, ia addr.IA) seg.Signer {
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
func sortedIntfs(intfs *ifstate.Interfaces, linkType topology.LinkType) []uint16 {
	var result []uint16
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

type topoWrap struct {
	Topo topology.Topology
}

func (w topoWrap) UnderlayNextHop(id uint16) *net.UDPAddr {
	a, _ := w.Topo.UnderlayNextHop(common.IFIDType(id))
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
			InternalAddr: netaddr.MustParseIPPort(info.InternalAddr.String()),
			RemoteID:     uint16(info.RemoteIFID),
			MTU:          uint16(info.MTU),
		}
	}
	return result
}
