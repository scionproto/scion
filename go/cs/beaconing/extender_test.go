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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
)

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
			intfs.Get(peer).Activate(graph.If_121_X_111_C)
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
			pseg, err := seg.CreateSegment(time.Now(), uint16(mrand.Int()))
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
		pseg, err := seg.CreateSegment(time.Now(), uint16(mrand.Int()))
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
				intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
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
				pseg, err := seg.CreateSegment(time.Now(), uint16(mrand.Int()))
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
