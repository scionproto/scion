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
	"hash"
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
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/proto"
)

func TestExtenderExtend(t *testing.T) {
	topoProvider := itopotest.TopoProviderFromFile(t, topoNonCore)
	mac, err := scrypto.InitMac(make([]byte, 16))
	require.NoError(t, err)
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	require.NoError(t, err)

	segDesc := []common.IFIDType{graph.If_120_X_111_B}
	peer := graph.If_111_C_121_X
	tests := []struct {
		name          string
		seg           []common.IFIDType
		inIfid        common.IFIDType
		egIfid        common.IFIDType
		inactivePeers []common.IFIDType
		errAssertion  assert.ErrorAssertionFunc
	}{
		{
			name:         "First hop, InIfid 0",
			egIfid:       graph.If_111_A_112_X,
			errAssertion: assert.NoError,
		},
		{
			name:         "First hop, EgIfid 0",
			inIfid:       graph.If_111_B_120_X,
			errAssertion: assert.Error,
		},
		{
			name:         "First hop, InIfid 0, EgIfid 0",
			errAssertion: assert.Error,
		},
		{
			name:         "First hop, both set",
			inIfid:       graph.If_111_B_120_X,
			egIfid:       graph.If_111_A_112_X,
			errAssertion: assert.Error,
		},
		{
			name:         "Second hop, InIfid 0",
			seg:          segDesc,
			egIfid:       graph.If_111_A_112_X,
			errAssertion: assert.Error,
		},
		{
			name:         "Second hop, EgIfid 0",
			seg:          segDesc,
			inIfid:       graph.If_111_B_120_X,
			errAssertion: assert.NoError,
		},
		{
			name:         "Second hop, InIfid 0, EgIfid 0",
			seg:          segDesc,
			errAssertion: assert.Error,
		},
		{
			name:         "Second hop, both set",
			seg:          segDesc,
			inIfid:       graph.If_111_B_120_X,
			egIfid:       graph.If_111_A_112_X,
			errAssertion: assert.NoError,
		},
		{
			name:          "Ignore provided, but inactive peer",
			seg:           segDesc,
			inIfid:        graph.If_111_B_120_X,
			egIfid:        graph.If_111_A_112_X,
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
			ext, err := ExtenderConf{
				MTU:           1337,
				Signer:        testSigner(t, priv, topoProvider.Get().IA()),
				Mac:           mac,
				Intfs:         intfs,
				GetMaxExpTime: maxExpTimeFactory(beacon.DefaultMaxExpTime),
			}.new()
			require.NoError(t, err)
			// Create path segment from description, if available.
			pseg, err := seg.NewSeg(&spath.InfoField{ISD: 1, TsInt: util.TimeToSecs(time.Now())})
			if len(test.seg) > 0 {
				pseg = testBeacon(g, test.seg).Segment
			}
			require.NoError(t, err)
			// Extend the segment.
			err = ext.extend(pseg, test.inIfid, test.egIfid, append(test.inactivePeers, peer))
			test.errAssertion(t, err)
			if err != nil {
				return
			}

			if test.egIfid == 0 {
				assert.NoError(t, pseg.Validate(seg.ValidateSegment))
			} else {
				assert.NoError(t, pseg.Validate(seg.ValidateBeacon))
			}

			err = pseg.VerifyASEntry(context.Background(), segVerifier(pub), pseg.MaxAEIdx())
			require.NoError(t, err)

			entry := pseg.ASEntries[pseg.MaxAEIdx()]
			t.Run("AS entry", func(t *testing.T) {
				assert.Equal(t, scrypto.Version(42), entry.CertVer)
				assert.Equal(t, scrypto.Version(84), entry.TrcVer)
				assert.Equal(t, uint8(DefaultIfidSize), entry.IfIDSize)
				assert.Equal(t, uint16(1337), entry.MTU)
				assert.Equal(t, topoProvider.Get().IA(), entry.IA())
				// Checks that inactive peers are ignored, even when provided.
				assert.Len(t, entry.HopEntries, 2)
			})
			infoF, err := pseg.InfoF()
			require.NoError(t, err)

			t.Run("hop entry check", func(t *testing.T) {
				var prev []byte
				// The extended hop entry is not the first one.
				if pseg.MaxAEIdx() > 0 {
					prev = pseg.ASEntries[pseg.MaxAEIdx()-1].HopEntries[0].RawHopField
				}
				testHopEntry(t, entry.HopEntries[0], intfs, test.inIfid, test.egIfid)
				testHopF(t, entry.HopEntries[0], mac, infoF.TsInt, ext.cfg.Signer.Meta().ExpTime,
					test.inIfid, test.egIfid, prev)
			})

			t.Run("peer entry is correct", func(t *testing.T) {
				testHopEntry(t, entry.HopEntries[1], intfs, peer, test.egIfid)
				testHopF(t, entry.HopEntries[1], mac, infoF.TsInt, ext.cfg.Signer.Meta().ExpTime,
					peer, test.egIfid, entry.HopEntries[0].RawHopField)
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
		ext, err := ExtenderConf{
			MTU:           1337,
			Signer:        testSigner(t, priv, topoProvider.Get().IA()),
			Mac:           mac,
			GetMaxExpTime: maxExpTimeFactory(1),
			Intfs:         intfs,
		}.new()
		require.NoError(t, err)
		pseg := testBeacon(g, segDesc).Segment
		err = ext.extend(pseg, graph.If_111_B_120_X, 0, []common.IFIDType{})
		require.NoError(t, err)
		hopF, err := pseg.ASEntries[pseg.MaxAEIdx()].HopEntries[0].HopField()
		require.NoError(t, err)
		assert.Equal(t, spath.ExpTimeType(1), hopF.ExpTime)

	})
	t.Run("segment is not extended on error", func(t *testing.T) {
		defaultSigner := func(t *testing.T) infra.Signer {
			return testSigner(t, priv, topoProvider.Get().IA())
		}
		tests := map[string]struct {
			Signer         func(t *testing.T) infra.Signer
			InIfID, EgIfID common.IFIDType
			Activate       func(intfs *ifstate.Interfaces)
		}{
			"Unknown Ingress IFID": {
				Signer:   defaultSigner,
				InIfID:   10,
				Activate: func(intfs *ifstate.Interfaces) {},
			},
			"Inactive Ingress IFID": {
				Signer:   defaultSigner,
				InIfID:   graph.If_111_B_120_X,
				Activate: func(intfs *ifstate.Interfaces) {},
			},
			"Invalid Ingress Remote IFID": {
				Signer: defaultSigner,
				InIfID: graph.If_111_B_120_X,
				Activate: func(intfs *ifstate.Interfaces) {
					intfs.Get(graph.If_111_B_120_X).Activate(0)
				},
			},
			"Unknown Egress IFID": {
				Signer: defaultSigner,
				InIfID: graph.If_111_B_120_X,
				EgIfID: 10,
				Activate: func(intfs *ifstate.Interfaces) {
					intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
				},
			},
			"Inactive Egress IFID": {
				Signer: defaultSigner,
				InIfID: graph.If_111_B_120_X,
				EgIfID: graph.If_111_A_112_X,
				Activate: func(intfs *ifstate.Interfaces) {
					intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
				},
			},
			"Invalid Egress Remote IFID": {
				Signer: defaultSigner,
				InIfID: graph.If_111_B_120_X,
				EgIfID: graph.If_111_A_112_X,
				Activate: func(intfs *ifstate.Interfaces) {
					intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
					intfs.Get(graph.If_111_A_112_X).Activate(0)
				},
			},
			"Signer expiration is to small": {
				Signer: func(t *testing.T) infra.Signer {
					signer, err := trust.NewSigner(
						trust.SignerConf{
							ChainVer: 42,
							TRCVer:   84,
							Validity: scrypto.Validity{NotAfter: util.UnixTime{Time: time.Now()}},
							Key: keyconf.Key{
								Type:      keyconf.PrivateKey,
								Algorithm: scrypto.Ed25519,
								Bytes:     priv,
								ID:        keyconf.ID{IA: topoProvider.Get().IA()},
							},
						},
					)
					require.NoError(t, err)
					return signer
				},
				InIfID: graph.If_111_B_120_X,
				Activate: func(intfs *ifstate.Interfaces) {
					intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
				},
			},
			"Signer fails": {
				Signer: func(t *testing.T) infra.Signer { return &failSigner{defaultSigner(t)} },
				InIfID: graph.If_111_B_120_X,
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
				require.NoError(t, err)
				test.Activate(intfs)

				ext, err := ExtenderConf{
					MTU:           1337,
					Signer:        test.Signer(t),
					Mac:           mac,
					Intfs:         intfs,
					GetMaxExpTime: maxExpTimeFactory(beacon.DefaultMaxExpTime),
				}.new()
				require.NoError(t, err)
				pseg := testBeacon(g, segDesc).Segment
				err = ext.extend(pseg, test.InIfID, test.EgIfID, []common.IFIDType{})
				assert.Error(t, err)
			})
		}
	})
}

// testHopF checks whether the hop field in the hop entry contains the expected
// values. The inIfid and prev are different between that cons and peer hop
// field.
func testHopF(t *testing.T, hop *seg.HopEntry, mac hash.Hash, ts uint32, signerExpTime time.Time,
	inIfid, egIfid common.IFIDType, prev []byte) {

	if prev != nil {
		prev = prev[1:]
	}
	hopF, err := spath.HopFFromRaw(hop.RawHopField)
	require.NoError(t, err)
	assert.Equal(t, inIfid, hopF.ConsIngress)
	assert.Equal(t, egIfid, hopF.ConsEgress)
	assert.NoError(t, hopF.Verify(mac, ts, prev))
	expiry, err := spath.ExpTimeFromDuration(signerExpTime.Sub(util.SecsToTime(ts)), false)
	require.NoError(t, err)
	assert.Equal(t, expiry, hopF.ExpTime)
}

// testHopEntry checks whether the hop entry contains the expected values. The
// inIfid is different between cons and peer hop entries.
func testHopEntry(t *testing.T, hop *seg.HopEntry, intfs *ifstate.Interfaces,
	inIfid, egIfid common.IFIDType) {

	ia, ifid, mtu := addr.IA{}, common.IFIDType(0), uint16(0)
	// Hop entries that are not first on the segment, must not
	// contain zero values.
	if inIfid != 0 {
		intf := intfs.Get(inIfid)
		if assert.NotNil(t, intf) {
			ia = intf.TopoInfo().IA
			ifid = intf.TopoInfo().RemoteIFID
			mtu = uint16(intf.TopoInfo().MTU)
		}
	}
	assert.Equal(t, ia, hop.InIA())
	assert.Equal(t, ifid, hop.RemoteInIF)
	assert.Equal(t, mtu, hop.InMTU)
	ia, ifid = addr.IA{}, common.IFIDType(0)
	// Hop entries that are not last on the segment, must not
	// contain zero values.
	if egIfid != 0 {
		intf := intfs.Get(egIfid)
		ia = intf.TopoInfo().IA
		ifid = intf.TopoInfo().RemoteIFID
	}
	assert.Equal(t, ia, hop.OutIA())
	assert.Equal(t, ifid, hop.RemoteOutIF)
}

type failSigner struct {
	infra.Signer
}

func (f *failSigner) Sign(msg []byte) (*proto.SignS, error) {
	return nil, errors.New("fail")
}

func maxExpTimeFactory(max spath.ExpTimeType) func() spath.ExpTimeType {
	return func() spath.ExpTimeType {
		return max
	}
}
