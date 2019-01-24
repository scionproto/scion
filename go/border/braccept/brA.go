// Copyright 2018 ETH Zurich
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

package main

import (
	"hash"

	"github.com/scionproto/scion/go/border/braccept/tpkt"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
)

var brACtrlScionHdr = tpkt.NewGenCmnHdr(
	"1-ff00:0:1", "192.168.0.101", "1-ff00:0:1", "BS_M", nil, common.L4UDP)

var IgnoredPacketsBrA = []*tpkt.ExpPkt{
	{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
		tpkt.GenOverlayIP4UDP("192.168.0.11", 30041, "192.168.0.61", 30041),
		brACtrlScionHdr,
		tpkt.NewUDP(20001, 0, &brACtrlScionHdr.ScionLayer, ifStateReq),
		ifStateReq,
	}}}

func genTestsBrA(hMac hash.Hash) []*BRTest {
	tests := []*BRTest{
		{
			Desc: "Single IFID peer - Xover peer/local",
			In: &tpkt.Pkt{
				Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(1, 1, tpkt.Segments{
							segment("(__P)[X_.261.0][X_.211.0][0.621]", nil),
							segment("(C__)[0.611][X_.121.0][X_.161.0]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.51", 30041),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(1, 1, tpkt.Segments{
							segment("(__P)[X_.261.0][X_.211.0][0.621]", nil),
							segment("(C__)[0.611][X_.121.0][X_.161.0]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrA,
		},
		// XXX should we check both segments have Peer flag set? currently not required
		{
			Desc: "Single IFID peer - Xover local/peer",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.11", 30001),
					tpkt.NewValidScion("1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(_SP)[X_.161.0][X_.121.0][_V.0.611]", hMac, 0, 1),
							segment("(C__)[_V.0.621][X_.211.0][X_.261.0]", nil)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							segment("(_SP)[X_.161.0][X_.121.0][_V.0.611]", hMac, 0, 1),
							segment("(C__)[_V.0.621][X_.211.0][X_.261.0]", nil)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrA,
		},
		{
			Desc: "Single IFID peer - Xover peer/child",
			In: &tpkt.Pkt{
				Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							segment("(__P)[X_.261.0][X_.211.0][0.621]", nil),
							segment("(CSP)[0.612][X_.121.151][X_.162.151][511.0]", hMac, 1, 2)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.14", 30004),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 2, tpkt.Segments{
							segment("(__P)[X_.261.0][X_.211.0][0.621]", nil),
							segment("(CSP)[0.612][X_.121.151][X_.162.151][511.0]", hMac, 1, 2)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrA,
		},
		{
			Desc: "Single IFID peer - Xover child/peer",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.13", 30003, "192.168.0.11", 30001),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(0, 2, tpkt.Segments{
							segment("(_SP)[511.0][X_.162.151][X_.121.151][_V.0.612]", hMac, 1, 2),
							segment("(C__)[_V.0.621][X_.211.0][X_.261.0]", nil)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							segment("(_SP)[511.0][X_.162.151][X_.121.151][_V.0.612]", hMac, 1, 2),
							segment("(C__)[_V.0.621][X_.211.0][X_.261.0]", nil)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrA,
		},
	}

	pktTriggerRev := tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1",
		tpkt.GenPath(0, 2, tpkt.Segments{
			segment("(_SP)[511.0][X_.162.151][X_.121.151][_V.0.612]", hMac, 1, 2),
			segment("(C__)[_V.0.621][X_.211.0][X_.261.0]", nil)},
		), nil,
		&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil)

	revScmpScionHdr := tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.11", "1-ff00:0:5", "172.16.5.1",
		tpkt.GenPath(1, 2, tpkt.Segments{
			segment("(___)[X_.261.0][X_.211.0][_V.0.621]", nil),
			segment("(CSP)[_V.0.612][X_.121.151][X_.162.151][511.0]", hMac, 1, 2)},
		),
		common.HopByHopClass)

	brCtrlScionHdr := tpkt.NewGenCmnHdr(
		"1-ff00:0:1", "192.168.0.61", "1-ff00:0:1", "192.168.0.101", nil, common.L4UDP)

	signedRevInfo := tpkt.MustSRevInfo(121, "1-ff00:0:1", "peer", tsNow32, 60)

	ifStateInfoDown := &tpkt.PathMgmtPld{
		Signer:      infra.NullSigner,
		SigVerifier: infra.NullSigVerifier,
		Instance: &path_mgmt.IFStateInfos{Infos: []*path_mgmt.IFStateInfo{
			{IfID: 121, Active: false, SRevInfo: signedRevInfo},
		}},
	}
	ifStateInfoUp := &tpkt.PathMgmtPld{
		Signer:      infra.NullSigner,
		SigVerifier: infra.NullSigVerifier,
		Instance: &path_mgmt.IFStateInfos{Infos: []*path_mgmt.IFStateInfo{
			{IfID: 121, Active: true, SRevInfo: nil},
		}},
	}
	revTest := &BRTest{
		Desc: "Single IFID peer - Revocation on interface owned",
		Pre: &tpkt.Pkt{
			Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
				tpkt.GenOverlayIP4UDP("192.168.0.61", 20006, "192.168.0.11", 30041),
				brCtrlScionHdr,
				tpkt.NewUDP(20006, 20001, &brCtrlScionHdr.ScionLayer, ifStateInfoDown),
				ifStateInfoDown,
			}},
		In: &tpkt.Pkt{
			Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
				tpkt.GenOverlayIP4UDP("192.168.0.13", 30003, "192.168.0.11", 30001),
				pktTriggerRev,
			}},
		Out: []*tpkt.ExpPkt{
			{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
				tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.13", 30003),
				revScmpScionHdr,
				&tpkt.ScionSCMPExtn{Extn: scmp.Extn{Error: true, HopByHop: true}},
				tpkt.NewSCMP(scmp.C_Path, scmp.T_P_RevokedIF, noTime,
					&revScmpScionHdr.ScionLayer,
					[]tpkt.LayerBuilder{
						pktTriggerRev,
					},
					tpkt.NewRevocation(0, 2, 121, false, signedRevInfo),
					common.L4UDP),
			}}},
		Post: &tpkt.Pkt{
			Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
				tpkt.GenOverlayIP4UDP("192.168.0.61", 20006, "192.168.0.11", 30041),
				brCtrlScionHdr,
				tpkt.NewUDP(20006, 20001, &brCtrlScionHdr.ScionLayer, ifStateInfoUp),
				ifStateInfoUp,
			}},
		Ignore: IgnoredPacketsBrA,
	}
	tests = append(tests, revTest)
	return tests
}
