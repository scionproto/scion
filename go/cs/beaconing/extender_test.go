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
	. "github.com/smartystreets/goconvey/convey"

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
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
	"github.com/scionproto/scion/go/proto"
)

func TestExtenderExtend(t *testing.T) {
	topoProvider := itopotest.TopoProviderFromFile(t, topoNonCore)
	mac, err := scrypto.InitMac(make(common.RawBytes, 16))
	xtest.FailOnErr(t, err)
	pub, priv, err := scrypto.GenKeyPair(scrypto.Ed25519)
	xtest.FailOnErr(t, err)

	segDesc := []common.IFIDType{graph.If_120_X_111_B}
	peer := graph.If_111_C_121_X
	tests := []struct {
		name          string
		seg           []common.IFIDType
		inIfid        common.IFIDType
		egIfid        common.IFIDType
		inactivePeers []common.IFIDType
		err           bool
	}{
		{
			name:   "First hop, InIfid 0",
			egIfid: graph.If_111_A_112_X,
		},
		{
			name:   "First hop, EgIfid 0",
			inIfid: graph.If_111_B_120_X,
			err:    true,
		},
		{
			name: "First hop, InIfid 0, EgIfid 0",
			err:  true,
		},
		{
			name:   "First hop, both set",
			inIfid: graph.If_111_B_120_X,
			egIfid: graph.If_111_A_112_X,
			err:    true,
		},
		{
			name:   "Second hop, InIfid 0",
			seg:    segDesc,
			egIfid: graph.If_111_A_112_X,
			err:    true,
		},
		{
			name:   "Second hop, EgIfid 0",
			seg:    segDesc,
			inIfid: graph.If_111_B_120_X,
		},
		{
			name: "Second hop, InIfid 0, EgIfid 0",
			seg:  segDesc,
			err:  true,
		},
		{
			name:   "Second hop, both set",
			seg:    segDesc,
			inIfid: graph.If_111_B_120_X,
			egIfid: graph.If_111_A_112_X,
		},
		{
			name:          "Ignore provided, but inactive peer",
			seg:           segDesc,
			inIfid:        graph.If_111_B_120_X,
			egIfid:        graph.If_111_A_112_X,
			inactivePeers: []common.IFIDType{graph.If_111_B_211_A},
		},
	}
	for _, test := range tests {
		Convey("Extend handles "+test.name+" correctly", t, func() {
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
			SoMsg("err", err, ShouldBeNil)
			// Create path segment from description, if available.
			pseg, err := seg.NewSeg(&spath.InfoField{ISD: 1, TsInt: util.TimeToSecs(time.Now())})
			if len(test.seg) > 0 {
				pseg = testBeacon(g, test.seg).Segment
			}
			xtest.FailOnErr(t, err)
			// Extend the segment.
			err = ext.extend(pseg, test.inIfid, test.egIfid, append(test.inactivePeers, peer))
			xtest.SoMsgError("err", err, test.err)
			if err != nil {
				return
			}
			Convey("Segment can be validated", func() {
				err := pseg.Validate(seg.ValidateBeacon)
				if test.egIfid == 0 {
					err = pseg.Validate(seg.ValidateSegment)
				}
				SoMsg("err", err, ShouldBeNil)
			})

			Convey("Segment is verifiable", func() {
				err := pseg.VerifyASEntry(context.Background(),
					segVerifier(pub), pseg.MaxAEIdx())
				SoMsg("err", err, ShouldBeNil)
			})
			entry := pseg.ASEntries[pseg.MaxAEIdx()]
			Convey("AS entry is correct", func() {
				SoMsg("ChainVer", entry.CertVer, ShouldEqual, 42)
				SoMsg("TRCVer", entry.TrcVer, ShouldEqual, 84)
				SoMsg("IfIDSize", entry.IfIDSize, ShouldEqual, DefaultIfidSize)
				SoMsg("MTU", entry.MTU, ShouldEqual, 1337)
				SoMsg("IA", entry.IA(), ShouldResemble, topoProvider.Get().IA())
				// Checks that inactive peers are ignored, even when provided.
				SoMsg("HopEntries length", len(entry.HopEntries), ShouldEqual, 2)
			})
			infoF, err := pseg.InfoF()
			SoMsg("infoF err", err, ShouldBeNil)

			Convey("Hop entry is correct", func() {
				var prev common.RawBytes
				// The extended hop entry is not the first one.
				if pseg.MaxAEIdx() > 0 {
					prev = pseg.ASEntries[pseg.MaxAEIdx()-1].HopEntries[0].RawHopField
				}
				testHopEntry(entry.HopEntries[0], intfs, test.inIfid, test.egIfid)
				testHopF(t, entry.HopEntries[0], mac, infoF.TsInt, ext.cfg.Signer.Meta().ExpTime,
					test.inIfid, test.egIfid, prev)
			})

			Convey("Peer entry is correct", func() {
				testHopEntry(entry.HopEntries[1], intfs, peer, test.egIfid)
				testHopF(t, entry.HopEntries[1], mac, infoF.TsInt, ext.cfg.Signer.Meta().ExpTime,
					peer, test.egIfid, entry.HopEntries[0].RawHopField)
			})
		})
	}
	Convey("The maximum expiration time is respected", t, func() {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		g := graph.NewDefaultGraph(mctrl)
		intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
		xtest.FailOnErr(t, err)
		intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
		ext, err := ExtenderConf{
			MTU:           1337,
			Signer:        testSigner(t, priv, topoProvider.Get().IA()),
			Mac:           mac,
			GetMaxExpTime: maxExpTimeFactory(1),
			Intfs:         intfs,
		}.new()
		SoMsg("err", err, ShouldBeNil)
		pseg := testBeacon(g, segDesc).Segment
		err = ext.extend(pseg, graph.If_111_B_120_X, 0, []common.IFIDType{})
		SoMsg("err", err, ShouldBeNil)
		hopF, err := pseg.ASEntries[pseg.MaxAEIdx()].HopEntries[0].HopField()
		SoMsg("err", err, ShouldBeNil)
		SoMsg("exp", hopF.ExpTime, ShouldEqual, 1)

	})
	Convey("Segment is not extended on error", t, func() {
		mctrl := gomock.NewController(t)
		defer mctrl.Finish()
		g := graph.NewDefaultGraph(mctrl)
		intfs := ifstate.NewInterfaces(topoProvider.Get().IFInfoMap(), ifstate.Config{})
		xtest.FailOnErr(t, err)
		ext, err := ExtenderConf{
			MTU:           1337,
			Signer:        testSigner(t, priv, topoProvider.Get().IA()),
			Mac:           mac,
			Intfs:         intfs,
			GetMaxExpTime: maxExpTimeFactory(beacon.DefaultMaxExpTime),
		}.new()
		SoMsg("err", err, ShouldBeNil)
		pseg := testBeacon(g, segDesc).Segment
		Convey("Unknown Ingress IFID", func() {
			err := ext.extend(pseg, 10, 0, []common.IFIDType{})
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("Inactive Ingress IFID", func() {
			err := ext.extend(pseg, graph.If_111_B_120_X, 0, []common.IFIDType{})
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("Invalid Ingress Remote IFID", func() {
			intfs.Get(graph.If_111_B_120_X).Activate(0)
			err := ext.extend(pseg, graph.If_111_B_120_X, 0, []common.IFIDType{})
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("Unknown Egress IFID", func() {
			intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
			err := ext.extend(pseg, graph.If_111_B_120_X, 10, []common.IFIDType{})
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("Inactive Egress IFID", func() {
			intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
			err := ext.extend(pseg, graph.If_111_B_120_X, graph.If_111_A_112_X, []common.IFIDType{})
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("Invalid Egress Remote IFID", func() {
			intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
			intfs.Get(graph.If_111_A_112_X).Activate(0)
			err := ext.extend(pseg, graph.If_111_B_120_X, graph.If_111_A_112_X, []common.IFIDType{})
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("Signer expiration is to small", func() {
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
			SoMsg("err", err, ShouldBeNil)
			ext.cfg.Signer = signer
			intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
			err = ext.extend(pseg, graph.If_111_B_120_X, 0, []common.IFIDType{})
			SoMsg("err", err, ShouldNotBeNil)
		})
		Convey("Signer fails", func() {
			ext.cfg.Signer = &failSigner{ext.cfg.Signer}
			intfs.Get(graph.If_111_B_120_X).Activate(graph.If_120_X_111_B)
			err = ext.extend(pseg, graph.If_111_B_120_X, 0, []common.IFIDType{})
			SoMsg("err", err, ShouldNotBeNil)
		})
	})
}

// testHopF checks whether the hop field in the hop entry contains the expected
// values. The inIfid and prev are different between that cons and peer hop
// field.
func testHopF(t *testing.T, hop *seg.HopEntry, mac hash.Hash, ts uint32, signerExpTime time.Time,
	inIfid, egIfid common.IFIDType, prev common.RawBytes) {

	if prev != nil {
		prev = prev[1:]
	}
	hopF, err := spath.HopFFromRaw(hop.RawHopField)
	SoMsg("err", err, ShouldBeNil)
	SoMsg("hopF.ConsIngress", hopF.ConsIngress, ShouldEqual, inIfid)
	SoMsg("hopF.ConsEgress", hopF.ConsEgress, ShouldEqual, egIfid)
	SoMsg("hopF.Mac", hopF.Verify(mac, ts, prev), ShouldBeNil)
	expiry, err := spath.ExpTimeFromDuration(signerExpTime.Sub(util.SecsToTime(ts)), false)
	xtest.FailOnErr(t, err)
	SoMsg("hopF.ExpTime", hopF.ExpTime, ShouldEqual, expiry)
}

// testHopEntry checks whether the hop entry contains the expected values. The
// inIfid is different between cons and peer hop entries.
func testHopEntry(hop *seg.HopEntry, intfs *ifstate.Interfaces, inIfid, egIfid common.IFIDType) {
	ia, ifid, mtu := addr.IA{}, common.IFIDType(0), uint16(0)
	// Hop entries that are not first on the segment, must not
	// contain zero values.
	if inIfid != 0 {
		intf := intfs.Get(inIfid)
		SoMsg("Intf", intf, ShouldNotBeNil)
		ia = intf.TopoInfo().IA
		ifid = intf.TopoInfo().RemoteIFID
		mtu = uint16(intf.TopoInfo().MTU)
	}
	SoMsg("Hop.InIA", hop.InIA(), ShouldResemble, ia)
	SoMsg("Hop.InIf", hop.RemoteInIF, ShouldEqual, ifid)
	SoMsg("hop.InMTU", hop.InMTU, ShouldEqual, mtu)
	ia, ifid = addr.IA{}, common.IFIDType(0)
	// Hop entries that are not last on the segment, must not
	// contain zero values.
	if egIfid != 0 {
		intf := intfs.Get(egIfid)
		ia = intf.TopoInfo().IA
		ifid = intf.TopoInfo().RemoteIFID
	}
	SoMsg("Hop.OutIA", hop.OutIA(), ShouldResemble, ia)
	SoMsg("Hop.OutIf", hop.RemoteOutIF, ShouldResemble, ifid)
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
