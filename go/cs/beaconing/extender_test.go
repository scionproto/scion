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
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/proto"
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

			ts := util.TimeToSecs(time.Now())
			rawInfo := make([]byte, spath.InfoFieldLength)
			(&spath.InfoField{
				ISD:   1,
				TsInt: ts,
			}).Write(rawInfo)

			pseg, err := seg.NewSeg(
				&seg.PathSegmentSignedData{
					RawInfo:      rawInfo,
					RawTimestamp: ts,
					SegID:        uint16(mrand.Int()),
					ISD:          1,
				},
			)
			require.NoError(t, err)

			// Create path segment from description, if available.
			if len(test.seg) > 0 {
				pseg = testBeacon(g, test.seg).Segment
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
				segVerifier{pubKey: pub}, pseg.MaxAEIdx())
			require.NoError(t, err)

			entry := pseg.ASEntries[pseg.MaxAEIdx()]
			t.Run("AS entry", func(t *testing.T) {
				assert.Equal(t, uint8(legacyIfIDSize), entry.IfIDSize)
				assert.Equal(t, uint16(1337), entry.MTU)
				assert.Equal(t, topoProvider.Get().IA(), entry.IA())
				// Checks that inactive peers are ignored, even when provided.
				assert.Len(t, entry.HopEntries, 2)
			})

			infoTS := pseg.Timestamp()
			t.Run("hop entry check", func(t *testing.T) {
				var prev []byte
				// The extended hop entry is not the first one.
				if pseg.MaxAEIdx() > 0 {
					prev = pseg.ASEntries[pseg.MaxAEIdx()-1].HopEntries[0].RawHopField
				}
				testHopEntry(t, entry.HopEntries[0], intfs, test.ingress, test.egress)
				testHopF(t, entry.HopEntries[0], mac, infoTS, ext.MaxExpTime(),
					test.ingress, test.egress, prev)
			})

			t.Run("peer entry is correct", func(t *testing.T) {
				testHopEntry(t, entry.HopEntries[1], intfs, peer, test.egress)
				testHopF(t, entry.HopEntries[1], mac, infoTS, ext.MaxExpTime(),
					peer, test.egress, entry.HopEntries[0].RawHopField)
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
		pseg := testBeacon(g, segDesc).Segment
		err = ext.Extend(context.Background(), pseg, graph.If_111_B_120_X, 0, []common.IFIDType{})
		require.NoError(t, err)
		hopF := pseg.ASEntries[pseg.MaxAEIdx()].HopEntries[0].HopField
		assert.Equal(t, uint8(1), hopF.ExpTime)

	})
	t.Run("segment is not extended on error", func(t *testing.T) {
		defaultSigner := func(t *testing.T) ctrl.Signer {
			return testSigner(t, priv, topoProvider.Get().IA())
		}
		tests := map[string]struct {
			Signer          func(t *testing.T) ctrl.Signer
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
				Signer:  func(t *testing.T) ctrl.Signer { return &failSigner{} },
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
				pseg := testBeacon(g, segDesc).Segment
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
func testHopF(t *testing.T, hop *seg.HopEntry, mac hash.Hash, ts time.Time,
	expTime spath.ExpTimeType, ingress, egress common.IFIDType, prev []byte) {

	if prev != nil {
		prev = prev[1:]
	}
	hopF, err := spath.HopFFromRaw(hop.RawHopField)
	require.NoError(t, err)
	assert.Equal(t, ingress, hopF.ConsIngress)
	assert.Equal(t, egress, hopF.ConsEgress)
	assert.NoError(t, hopF.Verify(mac, util.TimeToSecs(ts), prev))
	assert.Equal(t, expTime, hopF.ExpTime)
}

// testHopEntry checks whether the hop entry contains the expected values. The
// ingress is different between cons and peer hop entries.
func testHopEntry(t *testing.T, hop *seg.HopEntry, intfs *ifstate.Interfaces,
	ingress, egress common.IFIDType) {

	ia, remote, mtu := addr.IA{}, common.IFIDType(0), uint16(0)
	// Hop entries that are not first on the segment, must not
	// contain zero values.
	if ingress != 0 {
		intf := intfs.Get(ingress)
		if assert.NotNil(t, intf) {
			ia = intf.TopoInfo().IA
			remote = intf.TopoInfo().RemoteIFID
			mtu = uint16(intf.TopoInfo().MTU)
		}
	}
	assert.Equal(t, ia, hop.InIA())
	assert.Equal(t, remote, hop.RemoteInIF)
	assert.Equal(t, mtu, hop.InMTU)
	ia, remote = addr.IA{}, common.IFIDType(0)
	// Hop entries that are not last on the segment, must not
	// contain zero values.
	if egress != 0 {
		intf := intfs.Get(egress)
		ia = intf.TopoInfo().IA
		remote = intf.TopoInfo().RemoteIFID
	}
	assert.Equal(t, ia, hop.OutIA())
	assert.Equal(t, remote, hop.RemoteOutIF)
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
			pseg, err := seg.NewSeg(
				&seg.PathSegmentSignedData{
					RawTimestamp: util.TimeToSecs(time.Now()),
					SegID:        uint16(mrand.Int()),
				},
			)
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
				assert.Equal(t, uint8(16), entry.IfIDSize)
				assert.Equal(t, uint16(1337), entry.MTU)
				assert.Equal(t, topoProvider.Get().IA(), entry.IA())
				// Checks that unset peers are ignored, even when provided.
				assert.Len(t, entry.HopEntries, 2)
			})
			t.Run("hop entry check", func(t *testing.T) {
				intf := intfs.Get(tc.egress)
				ia := intf.TopoInfo().IA
				remote := intf.TopoInfo().RemoteIFID
				assert.Equal(t, ia, entry.HopEntries[0].OutIA())
				assert.Equal(t, remote, entry.HopEntries[0].RemoteOutIF)

				assert.Equal(t, uint16(tc.ingress), entry.HopEntries[0].HopField.ConsIngress)
				assert.Equal(t, uint16(tc.egress), entry.HopEntries[0].HopField.ConsEgress)
				assert.Equal(t, ext.MaxExpTime(), entry.HopEntries[0].HopField.ExpTime)
				// FIXME(roosd): Check hop field can be authenticated.
			})
			t.Run("peer entry check", func(t *testing.T) {
				intf := intfs.Get(tc.egress)
				ia := intf.TopoInfo().IA
				remote := intf.TopoInfo().RemoteIFID
				assert.Equal(t, ia, entry.HopEntries[1].OutIA())
				assert.Equal(t, remote, entry.HopEntries[1].RemoteOutIF)

				assert.Equal(t, uint16(peer), entry.HopEntries[1].HopField.ConsIngress)
				assert.Equal(t, uint16(tc.egress), entry.HopEntries[1].HopField.ConsEgress)
				assert.Equal(t, ext.MaxExpTime(), entry.HopEntries[1].HopField.ExpTime)
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
		pseg, err := seg.NewSeg(
			&seg.PathSegmentSignedData{
				RawTimestamp: util.TimeToSecs(time.Now()),
				SegID:        uint16(mrand.Int()),
			},
		)
		require.NoError(t, err)
		err = ext.Extend(context.Background(), pseg, 0, graph.If_111_A_112_X, []common.IFIDType{})
		require.NoError(t, err)
		assert.Equal(t, uint8(1), pseg.ASEntries[0].HopEntries[0].HopField.ExpTime)

	})
	t.Run("segment is not extended on error", func(t *testing.T) {
		defaultSigner := func(t *testing.T) ctrl.Signer {
			return testSigner(t, priv, topoProvider.Get().IA())
		}
		testCases := map[string]struct {
			Signer          func(t *testing.T) ctrl.Signer
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
				Signer:  func(t *testing.T) ctrl.Signer { return &failSigner{} },
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
				pseg, err := seg.NewSeg(
					&seg.PathSegmentSignedData{
						RawTimestamp: util.TimeToSecs(time.Now()),
						SegID:        uint16(mrand.Int()),
					},
				)
				require.NoError(t, err)
				err = ext.Extend(context.Background(), pseg, tc.Ingress, tc.Egress,
					[]common.IFIDType{})
				assert.Error(t, err)
			})
		}
	})
}

type failSigner struct {
}

func (f *failSigner) Sign(context.Context, []byte) (*proto.SignS, error) {
	return nil, errors.New("fail")
}

func maxExpTimeFactory(max spath.ExpTimeType) func() spath.ExpTimeType {
	return func() spath.ExpTimeType {
		return max
	}
}
