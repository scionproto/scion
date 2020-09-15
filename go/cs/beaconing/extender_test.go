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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"hash"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
)

func TestLegacyExtenderExtend(t *testing.T) {
	topoProvider := itopotest.TopoProviderFromFile(t, topoNonCore)
	mac, err := scrypto.InitMac(make([]byte, 16))
	require.NoError(t, err)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()

	segDesc := []common.IFIDType{graph.If_120_X_111_B}
	peer := graph.If_111_C_121_X
	tests := []struct {
		name          string
		seg           []common.IFIDType
		ingress       common.IFIDType
		egress        common.IFIDType
		inactivePeers []common.IFIDType
		errAssertion  assert.ErrorAssertionFunc
	}{
		{
			name:         "First hop, ingress 0",
			egress:       graph.If_111_A_112_X,
			errAssertion: assert.NoError,
		},
		{
			name:         "First hop, egress 0",
			ingress:      graph.If_111_B_120_X,
			errAssertion: assert.Error,
		},
		{
			name:         "First hop, ingress 0, egress 0",
			errAssertion: assert.Error,
		},
		{
			name:         "First hop, both set",
			ingress:      graph.If_111_B_120_X,
			egress:       graph.If_111_A_112_X,
			errAssertion: assert.Error,
		},
		{
			name:         "Second hop, ingress 0",
			seg:          segDesc,
			egress:       graph.If_111_A_112_X,
			errAssertion: assert.Error,
		},
		{
			name:         "Second hop, egress 0",
			seg:          segDesc,
			ingress:      graph.If_111_B_120_X,
			errAssertion: assert.NoError,
		},
		{
			name:         "Second hop, ingress 0, egress 0",
			seg:          segDesc,
			errAssertion: assert.Error,
		},
		{
			name:         "Second hop, both set",
			seg:          segDesc,
			ingress:      graph.If_111_B_120_X,
			egress:       graph.If_111_A_112_X,
			errAssertion: assert.NoError,
		},
		{
			name:          "Ignore provided, but inactive peer",
			seg:           segDesc,
			ingress:       graph.If_111_B_120_X,
			egress:        graph.If_111_A_112_X,
			inactivePeers: []common.IFIDType{graph.If_111_B_211_A},
			errAssertion:  assert.NoError,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			g := graph.NewDefaultGraph(mctrl)
			// Setup interfaces with active parent, child and one peer interface.
			intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
			intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
			intfs.Get(graph.If_111_A_112_X).Activate(graph.If_112_X_111_A)
			intfs.Get(peer).Activate(graph.If_121_X_111_C)
			ext := &LegacyExtender{
				IA:         topoProvider.Get().IA(),
				Signer:     testSigner(t, priv, topoProvider.Get().IA()),
				MAC:        func() hash.Hash { return mac },
				Intfs:      intfs,
				MTU:        1337,
				MaxExpTime: maxExpTimeFactory(beacon.DefaultMaxExpTime),
				StaticInfo: func() *StaticInfoCfg { return nil },
			}

			pseg, err := seg.CreateSegment(time.Now(), uint16(mrand.Int()), 1)
			require.NoError(t, err)

			// Create path segment from description, if available.
			if len(test.seg) > 0 {
				pseg = testBeacon(g, test.seg)
			}
			require.NoError(t, err)
			// Extend the segment.
			err = ext.Extend(context.Background(), pseg,
				test.ingress, test.egress, append(test.inactivePeers, peer))
			test.errAssertion(t, err)
			if err != nil {
				return
			}

			if test.egress == 0 {
				assert.NoError(t, pseg.Validate(seg.ValidateSegment))
			} else {
				assert.NoError(t, pseg.Validate(seg.ValidateBeacon))
			}

			err = pseg.VerifyASEntry(context.Background(),
				segVerifier{pubKey: pub}, pseg.MaxIdx())
			require.NoError(t, err)

			entry := pseg.ASEntries[pseg.MaxIdx()]
			t.Run("AS entry", func(t *testing.T) {
				assert.Equal(t, uint16(1337), entry.MTU)
				assert.Equal(t, topoProvider.Get().IA(), entry.Local)
				// Checks that inactive peers are ignored, even when provided.
				assert.Len(t, entry.PeerEntries, 1)
				if test.egress != 0 {
					intf := intfs.Get(test.egress)
					assert.Equal(t, intf.TopoInfo().IA, entry.Next)
				} else {
					assert.Equal(t, addr.IA{}, entry.Next)
				}

			})

			infoTS := pseg.Info.Timestamp
			t.Run("hop entry check", func(t *testing.T) {
				var prev []byte
				// The extended hop entry is not the first one.
				if pseg.MaxIdx() > 0 {
					hf := pseg.ASEntries[pseg.MaxIdx()-1].HopEntry.HopField
					prev = (&spath.HopField{
						ConsIngress: common.IFIDType(hf.ConsIngress),
						ConsEgress:  common.IFIDType(hf.ConsEgress),
						ExpTime:     spath.ExpTimeType(hf.ExpTime),
						Mac:         hf.MAC,
					}).Pack()
				}

				mtu := 0
				// Hop entries that are not first on the segment, must not
				// contain zero values.
				if test.ingress != 0 {
					intf := intfs.Get(test.ingress)
					require.NotNil(t, intf)
					mtu = int(intf.TopoInfo().MTU)
				}
				assert.Equal(t, mtu, entry.HopEntry.IngressMTU)

				testHopF(t, entry.HopEntry.HopField, mac, infoTS, ext.MaxExpTime(),
					test.ingress, test.egress, prev)
			})

			t.Run("peer entry is correct", func(t *testing.T) {

				hf := entry.HopEntry.HopField
				prev := (&spath.HopField{
					ConsIngress: common.IFIDType(hf.ConsIngress),
					ConsEgress:  common.IFIDType(hf.ConsEgress),
					ExpTime:     spath.ExpTimeType(hf.ExpTime),
					Mac:         hf.MAC,
				}).Pack()

				// Hop entries that are not first on the segment, must not
				// contain zero values.
				intf := intfs.Get(peer)
				require.NotNil(t, intf)
				ia := intf.TopoInfo().IA
				remote := uint16(intf.TopoInfo().RemoteIFID)
				mtu := int(intf.TopoInfo().MTU)

				peerEntry := entry.PeerEntries[0]

				assert.Equal(t, ia, peerEntry.Peer)
				assert.Equal(t, remote, peerEntry.PeerInterface)
				assert.Equal(t, mtu, peerEntry.PeerMTU)

				testHopF(t, peerEntry.HopField, mac, infoTS, ext.MaxExpTime(),
					peer, test.egress, prev)
			})
		})
	}
	t.Run("the maximum expiration time is respected", func(t *testing.T) {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		g := graph.NewDefaultGraph(mctrl)
		intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
		require.NoError(t, err)
		intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
		ext := &LegacyExtender{
			IA:         topoProvider.Get().IA(),
			Signer:     testSigner(t, priv, topoProvider.Get().IA()),
			MAC:        func() hash.Hash { return mac },
			Intfs:      intfs,
			MTU:        1337,
			MaxExpTime: maxExpTimeFactory(1),
			StaticInfo: func() *StaticInfoCfg { return nil },
		}
		require.NoError(t, err)
		pseg := testBeacon(g, segDesc)
		err = ext.Extend(context.Background(), pseg, graph.If_111_B_120_X, 0, []common.IFIDType{})
		require.NoError(t, err)
		hopF := pseg.ASEntries[pseg.MaxIdx()].HopEntry.HopField
		assert.Equal(t, uint8(1), hopF.ExpTime)

	})
	t.Run("segment is not extended on error", func(t *testing.T) {
		defaultSigner := func(t *testing.T) seg.Signer {
			return testSigner(t, priv, topoProvider.Get().IA())
		}
		tests := map[string]struct {
			Signer          func(t *testing.T) seg.Signer
			Ingress, Egress common.IFIDType
			Activate        func(intfs *ifstate.Interfaces)
		}{
			"Unknown Ingress": {
				Signer:   defaultSigner,
				Ingress:  10,
				Activate: func(intfs *ifstate.Interfaces) {},
			},
			"Inactive Ingress": {
				Signer:   defaultSigner,
				Ingress:  graph.If_111_B_120_X,
				Activate: func(intfs *ifstate.Interfaces) {},
			},
			"Invalid Ingress Remote": {
				Signer:  defaultSigner,
				Ingress: graph.If_111_B_120_X,
				Activate: func(intfs *ifstate.Interfaces) {
					intfs.Get(graph.If_111_B_120_X).Activate(0)
				},
			},
			"Unknown Egress": {
				Signer:  defaultSigner,
				Ingress: graph.If_111_B_120_X,
				Egress:  10,
				Activate: func(intfs *ifstate.Interfaces) {
					intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
				},
			},
			"Inactive Egress": {
				Signer:  defaultSigner,
				Ingress: graph.If_111_B_120_X,
				Egress:  graph.If_111_A_112_X,
				Activate: func(intfs *ifstate.Interfaces) {
					intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
				},
			},
			"Invalid Egress Remote": {
				Signer:  defaultSigner,
				Ingress: graph.If_111_B_120_X,
				Egress:  graph.If_111_A_112_X,
				Activate: func(intfs *ifstate.Interfaces) {
					intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
					intfs.Get(graph.If_111_A_112_X).Activate(0)
				},
			},
			"Signer fails": {
				Signer:  func(t *testing.T) seg.Signer { return &failSigner{} },
				Ingress: graph.If_111_B_120_X,
				Activate: func(intfs *ifstate.Interfaces) {
					intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
				},
			},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				mctrl := gomock.NewController(t)
				defer mctrl.Finish()
				g := graph.NewDefaultGraph(mctrl)
				intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
				test.Activate(intfs)

				ext := &LegacyExtender{
					IA:         topoProvider.Get().IA(),
					Signer:     test.Signer(t),
					MAC:        func() hash.Hash { return mac },
					Intfs:      intfs,
					MTU:        1337,
					MaxExpTime: maxExpTimeFactory(beacon.DefaultMaxExpTime),
					StaticInfo: func() *StaticInfoCfg { return nil },
				}
				pseg := testBeacon(g, segDesc)
				err = ext.Extend(context.Background(), pseg,
					test.Ingress, test.Egress, []common.IFIDType{})
				assert.Error(t, err)
			})
		}
	})
}

// testHopF checks whether the hop field in the hop entry contains the expected
// values. The ingress and prev are different between that cons and peer hop
// field.
func testHopF(t *testing.T, hop seg.HopField, mac hash.Hash, ts time.Time,
	expTime spath.ExpTimeType, ingress, egress common.IFIDType, prev []byte) {

	if prev != nil {
		prev = prev[1:]
	}
	hopF := spath.HopField{
		ConsIngress: common.IFIDType(hop.ConsIngress),
		ConsEgress:  common.IFIDType(hop.ConsEgress),
		ExpTime:     spath.ExpTimeType(hop.ExpTime),
		Mac:         hop.MAC,
	}
	assert.Equal(t, ingress, hopF.ConsIngress)
	assert.Equal(t, egress, hopF.ConsEgress)
	assert.NoError(t, hopF.Verify(mac, util.TimeToSecs(ts), prev))
	assert.Equal(t, expTime, hopF.ExpTime)
}

func TestDefaultExtenderExtend(t *testing.T) {
	topoProvider := itopotest.TopoProviderFromFile(t, topoNonCore)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()

	peer := graph.If_111_C_121_X
	testsCases := map[string]struct {
		ingress      common.IFIDType
		egress       common.IFIDType
		unsetPeers   []common.IFIDType
		errAssertion assert.ErrorAssertionFunc
	}{
		"valid": {
			egress:       graph.If_111_A_112_X,
			errAssertion: assert.NoError,
		},
		"ignore unset peers": {
			egress:       graph.If_111_A_112_X,
			unsetPeers:   []common.IFIDType{graph.If_111_B_211_A},
			errAssertion: assert.NoError,
		},
		"egress 0": {
			ingress:      graph.If_111_B_120_X,
			errAssertion: assert.Error,
		},
		"ingress and egress 0": {
			errAssertion: assert.Error,
		},
		"ingress 0": {
			ingress:      graph.If_111_B_120_X,
			egress:       graph.If_111_A_112_X,
			errAssertion: assert.Error,
		},
	}
	for name, tc := range testsCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			mctrl := gomock.NewController(t)
			defer mctrl.Finish()
			// Setup interfaces with active parent, child and one peer interface.
			intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
			intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
			intfs.Get(graph.If_111_A_112_X).Activate(graph.If_112_X_111_A)
			intfs.Get(peer).Activate(graph.If_121_X_111_C)
			intfs.Get(peer).SetState(ifstate.Revoked)
			ext := &DefaultExtender{
				IA:     topoProvider.Get().IA(),
				Signer: testSigner(t, priv, topoProvider.Get().IA()),
				MAC: func() hash.Hash {
					mac, err := scrypto.InitMac(make([]byte, 16))
					require.NoError(t, err)
					return mac
				},
				Intfs:      intfs,
				MTU:        1337,
				MaxExpTime: func() uint8 { return uint8(beacon.DefaultMaxExpTime) },
				StaticInfo: func() *StaticInfoCfg { return nil },
			}
			pseg, err := seg.CreateSegment(time.Now(), uint16(mrand.Int()), 0)
			require.NoError(t, err)

			// Extend the segment.
			err = ext.Extend(context.Background(), pseg, tc.ingress, tc.egress,
				append(tc.unsetPeers, peer))
			tc.errAssertion(t, err)
			if err != nil {
				return
			}
			assert.NoError(t, pseg.Validate(seg.ValidateBeacon))

			err = pseg.VerifyASEntry(context.Background(), segVerifier{pubKey: pub}, 0)
			require.NoError(t, err)

			entry := pseg.ASEntries[0]
			t.Run("AS entry", func(t *testing.T) {
				intf := intfs.Get(tc.egress)
				ia := intf.TopoInfo().IA

				assert.Equal(t, 1337, entry.MTU)
				assert.Equal(t, topoProvider.Get().IA(), entry.Local)
				assert.Equal(t, ia, entry.Next)
				// Checks that unset peers are ignored, even when provided.
				assert.Len(t, entry.PeerEntries, 1)
			})
			t.Run("hop entry check", func(t *testing.T) {
				assert.Equal(t, uint16(tc.ingress), entry.HopEntry.HopField.ConsIngress)
				assert.Equal(t, uint16(tc.egress), entry.HopEntry.HopField.ConsEgress)
				assert.Equal(t, ext.MaxExpTime(), entry.HopEntry.HopField.ExpTime)
				// FIXME(roosd): Check hop field can be authenticated.
			})
			t.Run("peer entry check", func(t *testing.T) {

				assert.Equal(t, uint16(peer), entry.PeerEntries[0].HopField.ConsIngress)
				assert.Equal(t, uint16(tc.egress), entry.PeerEntries[0].HopField.ConsEgress)
				assert.Equal(t, ext.MaxExpTime(), entry.PeerEntries[0].HopField.ExpTime)
				// FIXME(roosd): Check hop field can be authenticated.
			})
		})
	}
	t.Run("the maximum expiration time is respected", func(t *testing.T) {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
		require.NoError(t, err)
		intfs.Get(graph.If_111_A_112_X).Activate(graph.If_112_X_111_A)
		ext := &DefaultExtender{
			IA:     topoProvider.Get().IA(),
			Signer: testSigner(t, priv, topoProvider.Get().IA()),
			MAC: func() hash.Hash {
				mac, err := scrypto.InitMac(make([]byte, 16))
				require.NoError(t, err)
				return mac
			},
			Intfs:      intfs,
			MTU:        1337,
			MaxExpTime: func() uint8 { return 1 },
			StaticInfo: func() *StaticInfoCfg { return nil },
		}
		require.NoError(t, err)
		pseg, err := seg.CreateSegment(time.Now(), uint16(mrand.Int()), 0)
		require.NoError(t, err)
		err = ext.Extend(context.Background(), pseg, 0, graph.If_111_A_112_X, []common.IFIDType{})
		require.NoError(t, err)
		assert.Equal(t, uint8(1), pseg.ASEntries[0].HopEntry.HopField.ExpTime)

	})
	t.Run("segment is not extended on error", func(t *testing.T) {
		defaultSigner := func(t *testing.T) seg.Signer {
			return testSigner(t, priv, topoProvider.Get().IA())
		}
		testCases := map[string]struct {
			Signer          func(t *testing.T) seg.Signer
			Ingress, Egress common.IFIDType
			Activate        func(intfs *ifstate.Interfaces)
		}{
			"Unknown Ingress": {
				Signer:   defaultSigner,
				Ingress:  10,
				Activate: func(intfs *ifstate.Interfaces) {},
			},
			"Inactive Ingress": {
				Signer:   defaultSigner,
				Ingress:  graph.If_111_B_120_X,
				Activate: func(intfs *ifstate.Interfaces) {},
			},
			"Invalid Ingress Remote": {
				Signer:  defaultSigner,
				Ingress: graph.If_111_B_120_X,
				Activate: func(intfs *ifstate.Interfaces) {
					intfs.Get(graph.If_111_B_120_X).Activate(0)
				},
			},
			"Unknown Egress": {
				Signer:  defaultSigner,
				Ingress: graph.If_111_B_120_X,
				Egress:  10,
				Activate: func(intfs *ifstate.Interfaces) {
					intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
				},
			},
			"Inactive Egress": {
				Signer:  defaultSigner,
				Ingress: graph.If_111_B_120_X,
				Egress:  graph.If_111_A_112_X,
				Activate: func(intfs *ifstate.Interfaces) {
					intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
				},
			},
			"Invalid Egress Remote": {
				Signer:  defaultSigner,
				Ingress: graph.If_111_B_120_X,
				Egress:  graph.If_111_A_112_X,
				Activate: func(intfs *ifstate.Interfaces) {
					intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
					intfs.Get(graph.If_111_A_112_X).Activate(0)
				},
			},
			"Signer fails": {
				Signer:  func(t *testing.T) seg.Signer { return &failSigner{} },
				Ingress: graph.If_111_B_120_X,
				Activate: func(intfs *ifstate.Interfaces) {
					intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
				},
			},
		}
		for name, tc := range testCases {
			name, tc := name, tc
			t.Run(name, func(t *testing.T) {
				mctrl := gomock.NewController(t)
				defer mctrl.Finish()
				intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
				tc.Activate(intfs)
				ext := &DefaultExtender{
					IA:     topoProvider.Get().IA(),
					Signer: testSigner(t, priv, topoProvider.Get().IA()),
					MAC: func() hash.Hash {
						mac, err := scrypto.InitMac(make([]byte, 16))
						require.NoError(t, err)
						return mac
					},
					Intfs:      intfs,
					MTU:        1337,
					MaxExpTime: func() uint8 { return uint8(beacon.DefaultMaxExpTime) },
					StaticInfo: func() *StaticInfoCfg { return nil },
				}
				pseg, err := seg.CreateSegment(time.Now(), uint16(mrand.Int()), 0)
				require.NoError(t, err)
				err = ext.Extend(context.Background(), pseg, tc.Ingress, tc.Egress,
					[]common.IFIDType{})
				assert.Error(t, err)
			})
		}
	})
}

type failSigner struct{}

func (f *failSigner) Sign(context.Context, []byte, ...[]byte) (*cryptopb.SignedMessage, error) {
	return nil, errors.New("fail")
}

func maxExpTimeFactory(max spath.ExpTimeType) func() spath.ExpTimeType {
	return func() spath.ExpTimeType {
		return max
	}
}

func testBeacon(g *graph.Graph, ifids []common.IFIDType) *seg.PathSegment {
	bseg := g.Beacon(ifids)
	bseg.ASEntries = bseg.ASEntries[:len(bseg.ASEntries)-1]
	return bseg
}
