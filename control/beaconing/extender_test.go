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

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/control/ifstate"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/topology"
)

func TestDefaultExtenderExtend(t *testing.T) {
	topo, err := topology.FromJSONFile(topoNonCore)
	require.NoError(t, err)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()

	peerRemoteIfs := map[uint16]uint16{
		graph.If_111_C_121_X: graph.If_121_X_111_C,
		graph.If_111_C_211_A: graph.If_211_A_111_C,
	}
	testsCases := map[string]struct {
		ingress      uint16
		egress       uint16
		peers        []uint16
		unsetPeers   []uint16
		errAssertion assert.ErrorAssertionFunc
	}{
		"valid": {
			egress:       graph.If_111_A_112_X,
			errAssertion: assert.NoError,
			peers:        []uint16{graph.If_111_C_121_X},
		},
		"two peers": {
			egress:       graph.If_111_A_112_X,
			peers:        []uint16{graph.If_111_C_121_X, graph.If_111_C_211_A},
			errAssertion: assert.NoError,
		},
		"ignore unset peers": {
			egress:       graph.If_111_A_112_X,
			peers:        []uint16{graph.If_111_C_121_X, graph.If_111_C_211_A},
			unsetPeers:   []uint16{graph.If_111_B_211_A},
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
			intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
			for _, peer := range tc.peers {
				intfs.Get(peer).Activate(peerRemoteIfs[peer])
			}
			ext := &beaconing.DefaultExtender{
				IA:     topo.IA(),
				Signer: testSigner(t, priv, topo.IA()),
				MAC: func() hash.Hash {
					mac, err := scrypto.InitMac(make([]byte, 16))
					require.NoError(t, err)
					return mac
				},
				Intfs:      intfs,
				MTU:        1337,
				MaxExpTime: func() uint8 { return beacon.DefaultMaxExpTime },
				StaticInfo: func() *beaconing.StaticInfoCfg { return nil },
			}
			pseg, err := seg.CreateSegment(time.Time{}, 0)
			require.NoError(t, err)

			// Extend the segment.
			err = ext.Extend(context.Background(), pseg, tc.ingress, tc.egress,
				append(tc.peers, tc.unsetPeers...))
			tc.errAssertion(t, err)
			if err != nil {
				return
			}
			assert.NoError(t, pseg.Validate(seg.ValidateBeacon))

			err = pseg.VerifyASEntry(context.Background(), segVerifier{pubKey: pub}, 0)
			require.NoError(t, err)

			t.Run("parsable", func(t *testing.T) {
				pb := seg.PathSegmentToPB(pseg)
				if tc.egress == 0 {
					cpseg, err := seg.SegmentFromPB(pb)
					require.NoError(t, err)
					assert.Equal(t, pseg, cpseg)
					return
				}
				cpseg, err := seg.BeaconFromPB(pb)
				require.NoError(t, err)
				assert.Equal(t, pseg, cpseg)
			})

			entry := pseg.ASEntries[0]
			t.Run("AS entry", func(t *testing.T) {
				intf := intfs.Get(tc.egress)
				ia := intf.TopoInfo().IA

				assert.Equal(t, 1337, entry.MTU)
				assert.Equal(t, topo.IA(), entry.Local)
				assert.Equal(t, ia, entry.Next)
				// Checks that unset peers are ignored, even when provided.
				assert.Len(t, entry.PeerEntries, len(tc.peers))
			})
			t.Run("hop entry check", func(t *testing.T) {
				assert.Equal(t, tc.ingress, entry.HopEntry.HopField.ConsIngress)
				assert.Equal(t, tc.egress, entry.HopEntry.HopField.ConsEgress)
				assert.Equal(t, ext.MaxExpTime(), entry.HopEntry.HopField.ExpTime)
				// FIXME(roosd): Check hop field can be authenticated.
			})
			t.Run("peer entry check", func(t *testing.T) {
				for i := range tc.peers {
					assert.Equal(t, tc.peers[i], entry.PeerEntries[i].HopField.ConsIngress)
					assert.Equal(t, tc.egress, entry.PeerEntries[i].HopField.ConsEgress)
					assert.Equal(t, ext.MaxExpTime(), entry.PeerEntries[i].HopField.ExpTime)
					// FIXME(roosd): Check hop field can be authenticated.
				}
			})
		})
	}
	t.Run("the maximum expiration time is respected", func(t *testing.T) {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
		require.NoError(t, err)
		ext := &beaconing.DefaultExtender{
			IA:     topo.IA(),
			Signer: testSigner(t, priv, topo.IA()),
			MAC: func() hash.Hash {
				mac, err := scrypto.InitMac(make([]byte, 16))
				require.NoError(t, err)
				return mac
			},
			Intfs:      intfs,
			MTU:        1337,
			MaxExpTime: func() uint8 { return 1 },
			StaticInfo: func() *beaconing.StaticInfoCfg { return nil },
		}
		require.NoError(t, err)
		pseg, err := seg.CreateSegment(time.Now(), uint16(mrand.Int()))
		require.NoError(t, err)
		err = ext.Extend(context.Background(), pseg, 0, graph.If_111_A_112_X, []uint16{})
		require.NoError(t, err)
		assert.Equal(t, uint8(1), pseg.ASEntries[0].HopEntry.HopField.ExpTime)

	})
	t.Run("segment is not extended on error", func(t *testing.T) {
		defaultSigner := func(t *testing.T) seg.Signer {
			return testSigner(t, priv, topo.IA())
		}
		testCases := map[string]struct {
			Signer          func(t *testing.T) seg.Signer
			Ingress, Egress uint16
		}{
			"Unknown Ingress": {
				Signer:  defaultSigner,
				Ingress: 10,
			},
			"Inactive Ingress": {
				Signer:  defaultSigner,
				Ingress: graph.If_111_B_120_X,
			},
			"Invalid Ingress Remote": {
				Signer:  defaultSigner,
				Ingress: graph.If_111_B_120_X,
			},
			"Unknown Egress": {
				Signer:  defaultSigner,
				Ingress: graph.If_111_B_120_X,
				Egress:  10,
			},
			"Inactive Egress": {
				Signer:  defaultSigner,
				Ingress: graph.If_111_B_120_X,
				Egress:  graph.If_111_A_112_X,
			},
			"Invalid Egress Remote": {
				Signer:  defaultSigner,
				Ingress: graph.If_111_B_120_X,
				Egress:  graph.If_111_A_112_X,
			},
			"Signer fails": {
				Signer:  func(t *testing.T) seg.Signer { return &failSigner{} },
				Ingress: graph.If_111_B_120_X,
			},
		}
		for name, tc := range testCases {
			name, tc := name, tc
			t.Run(name, func(t *testing.T) {
				mctrl := gomock.NewController(t)
				defer mctrl.Finish()
				intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
				ext := &beaconing.DefaultExtender{
					IA:     topo.IA(),
					Signer: testSigner(t, priv, topo.IA()),
					MAC: func() hash.Hash {
						mac, err := scrypto.InitMac(make([]byte, 16))
						require.NoError(t, err)
						return mac
					},
					Intfs:      intfs,
					MTU:        1337,
					MaxExpTime: func() uint8 { return beacon.DefaultMaxExpTime },
					StaticInfo: func() *beaconing.StaticInfoCfg { return nil },
				}
				pseg, err := seg.CreateSegment(time.Now(), uint16(mrand.Int()))
				require.NoError(t, err)
				err = ext.Extend(context.Background(), pseg, tc.Ingress, tc.Egress,
					[]uint16{})
				assert.Error(t, err)
			})
		}
	})
}

type failSigner struct{}

func (f *failSigner) Sign(context.Context, []byte, ...[]byte) (*cryptopb.SignedMessage, error) {
	return nil, errors.New("fail")
}
