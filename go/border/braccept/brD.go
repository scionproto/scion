// +build ignore
//
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
	"time"

	"github.com/scionproto/scion/go/border/braccept/layers"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/scmp"
)

var brDCtrlScionHdr = layers.NewGenCmnHdr(
	"1-ff00:0:1", "192.168.0.104", "1-ff00:0:1", "BS_M", nil, common.L4UDP)

var IgnoredPacketsBrD = []*layers.ExpPkt{
	{Dev: "ifid_local", Layers: []layers.LayerMatcher{
		layers.GenOverlayIP4UDP("192.168.0.14", 30041, "192.168.0.61", 30041),
		brDCtrlScionHdr,
		layers.NewUDP(20004, 0, &brDCtrlScionHdr.ScionLayer, ifStateReq),
		ifStateReq,
	}}}

func genTestsBrD(hMac hash.Hash) []*BRTest {
	tests := []*BRTest{
		{
			Desc: "Multiple IFIDs - child/local",
			In: &layers.Pkt{
				Dev: "ifid_151", Layers: []layers.LayerBuilder{
					layers.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
					layers.NewValidScion("1-ff00:0:5", "172.16.4.1", "1-ff00:0:1", "192.168.0.51",
						layers.GenPath(0, 1, layers.Segments{
							segment("(___)[511.0][0.151]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*layers.ExpPkt{
				{Dev: "ifid_local", Layers: []layers.LayerMatcher{
					layers.GenOverlayIP4UDP("192.168.0.14", 30004, "192.168.0.51", 30041),
					layers.NewGenCmnHdr("1-ff00:0:5", "172.16.4.1", "1-ff00:0:1", "192.168.0.51",
						layers.GenPath(0, 1, layers.Segments{
							segment("(___)[511.0][0.151]", hMac, 1)},
						),
						common.L4UDP),
					layers.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrD,
		},
		{
			Desc: "Multiple IFIDs - local/child",
			In: &layers.Pkt{
				Dev: "ifid_local", Layers: []layers.LayerBuilder{
					layers.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.14", 30004),
					layers.NewValidScion("1-ff00:0:1", "192.168.0.51", "1-ff00:0:5", "172.16.4.1",
						layers.GenPath(0, 0, layers.Segments{
							segment("(C__)[0.151][511.0]", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*layers.ExpPkt{
				{Dev: "ifid_151", Layers: []layers.LayerMatcher{
					layers.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
					layers.NewGenCmnHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:5", "172.16.4.1",
						layers.GenPath(0, 1, layers.Segments{
							segment("(C__)[0.151][511.0]", hMac, 0)},
						),
						common.L4UDP),
					layers.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrD,
		},
		{
			Desc: "Multiple IFIDs - child/parent",
			In: &layers.Pkt{
				Dev: "ifid_151", Layers: []layers.LayerBuilder{
					layers.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
					layers.NewValidScion("1-ff00:0:5", "172.16.4.1", "1-ff00:0:6", "172.16.6.1",
						layers.GenPath(0, 1, layers.Segments{
							segment("(___)[511.0][162.151][0.612]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*layers.ExpPkt{
				{Dev: "ifid_162", Layers: []layers.LayerMatcher{
					layers.GenOverlayIP4UDP("192.168.16.4", 50000, "192.168.16.5", 40000),
					layers.NewGenCmnHdr("1-ff00:0:5", "172.16.4.1", "1-ff00:0:6", "172.16.6.1",
						layers.GenPath(0, 2, layers.Segments{
							segment("(___)[511.0][162.151][0.612]", hMac, 1)},
						),
						common.L4UDP),
					layers.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrD,
		},
		{
			Desc: "Multiple IFIDs - parent/child",
			In: &layers.Pkt{
				Dev: "ifid_162", Layers: []layers.LayerBuilder{
					layers.GenOverlayIP4UDP("192.168.16.5", 40000, "192.168.16.4", 50000),
					layers.NewValidScion("1-ff00:0:6", "172.16.6.1", "1-ff00:0:5", "172.16.4.1",
						layers.GenPath(0, 1, layers.Segments{
							segment("(C__)[0.612][162.151][511.0]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*layers.ExpPkt{
				{Dev: "ifid_151", Layers: []layers.LayerMatcher{
					layers.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
					layers.NewGenCmnHdr("1-ff00:0:6", "172.16.6.1", "1-ff00:0:5", "172.16.4.1",
						layers.GenPath(0, 2, layers.Segments{
							segment("(C__)[0.612][162.151][511.0]", hMac, 1)},
						),
						common.L4UDP),
					layers.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrD,
		},
		{
			Desc: "Multiple IFIDs - Xover child/peer",
			In: &layers.Pkt{
				Dev: "ifid_151", Layers: []layers.LayerBuilder{
					layers.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
					layers.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:3", "172.16.3.1",
						layers.GenPath(0, 1, layers.Segments{
							segment("(_SP)[511.0][X_.162.151][X_.131.151][_V.0.612]", hMac, 1, 2),
							segment("(C__)[_V.0.831][X_.311.0][X_.381.0]", nil)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*layers.ExpPkt{
				{Dev: "ifid_131", Layers: []layers.LayerMatcher{
					layers.GenOverlayIP4UDP("192.168.13.2", 50000, "192.168.13.3", 40000),
					layers.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:3", "172.16.3.1",
						layers.GenPath(1, 1, layers.Segments{
							segment("(_SP)[511.0][X_.162.151][X_.131.151][_V.0.612]", hMac, 1, 2),
							segment("(C__)[_V.0.831][X_.311.0][X_.381.0]", nil)},
						),
						common.L4UDP),
					layers.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrD,
		},
		{
			Desc: "Multiple IFIDs - Xover peer/child",
			In: &layers.Pkt{
				Dev: "ifid_131", Layers: []layers.LayerBuilder{
					layers.GenOverlayIP4UDP("192.168.13.3", 40000, "192.168.13.2", 50000),
					layers.NewValidScion("1-ff00:0:3", "173.16.3.1", "1-ff00:0:5", "172.16.5.1",
						layers.GenPath(1, 1, layers.Segments{
							segment("(_SP)[X_.381.0][X_.311.0][_V.0.831]", nil),
							segment("(CSP)[_V.0.612][X_.131.151][X_.162.151][511.0]", hMac, 1, 2)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*layers.ExpPkt{
				{Dev: "ifid_151", Layers: []layers.LayerMatcher{
					layers.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
					layers.NewGenCmnHdr("1-ff00:0:3", "173.16.3.1", "1-ff00:0:5", "172.16.5.1",
						layers.GenPath(1, 3, layers.Segments{
							segment("(_SP)[X_.381.0][X_.311.0][_V.0.831]", nil),
							segment("(CSP)[_V.0.612][X_.131.151][X_.162.151][511.0]", hMac, 1, 2)},
						),
						common.L4UDP),
					layers.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrD,
		},
		{
			Desc: "Multiple IFIDs - Xover child/child",
			In: &layers.Pkt{
				Dev: "ifid_142", Layers: []layers.LayerBuilder{
					layers.GenOverlayIP4UDP("192.168.14.5", 40000, "192.168.14.4", 50000),
					layers.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:5", "172.16.5.1",
						layers.GenPath(0, 1, layers.Segments{
							segment("(_S_)[412.0][X_.162.142][_V.0.612]", hMac, 1),
							segment("(CS_)[_V.0.612][X_.162.151][511.0]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*layers.ExpPkt{
				{Dev: "ifid_151", Layers: []layers.LayerMatcher{
					layers.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
					layers.NewGenCmnHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:5", "172.16.5.1",
						layers.GenPath(1, 2, layers.Segments{
							segment("(_S_)[412.0][X_.162.142][_V.0.612]", hMac, 1),
							segment("(CS_)[_V.0.612][X_.162.151][511.0]", hMac, 1)},
						),
						common.L4UDP),
					layers.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrD,
		},
	}
	// We use a known IP ie. CS, so we already have ARP entry for it
	revScionHdr := layers.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:1", "192.168.0.71",
		layers.GenPath(0, 2, layers.Segments{
			segment("(___)[999.0][511.512][0.151]", hMac, 2)},
		),
		common.HopByHopClass)

	sRevInfo := layers.MustSRevInfo(512, "1-ff00:0:5", "child", tsNow32, 60)
	rev := layers.NewRevocation(0, 1, 512, false, sRevInfo)

	revScmpHdrPld := layers.NewSCMP(scmp.C_Path, scmp.T_P_RevokedIF, now,
		&revScionHdr.ScionLayer, []layers.LayerBuilder{
			layers.NewValidScion("1-ff00:0:1", "192.168.0.71", "1-ff00:0:9", "172.16.9.1",
				layers.GenPath(0, 1, layers.Segments{
					segment("(C__)[0.151][511.512][999.0]", hMac, 0)},
				), nil,
				&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil)},
		rev,
		common.L4UDP)

	revPsScionHdr := layers.NewGenCmnHdr("1-ff00:0:1", "192.168.0.104", "1-ff00:0:1", "PS",
		nil, common.L4UDP)
	revPsPld := &layers.PathMgmtPld{
		Signer:      infra.NullSigner,
		SigVerifier: infra.NullSigVerifier,
		Instance:    sRevInfo,
	}

	revLocalFork := &BRTest{
		Desc:    "Multiple IFIDs - Revocation to local destination, fork to PS",
		Timeout: 1 * time.Second, // Control packets need to go through the dispatcher
		In: &layers.Pkt{
			Dev: "ifid_151", Layers: []layers.LayerBuilder{
				layers.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
				revScionHdr,
				layers.NewSCMPExtn(common.L4SCMP, layers.ExtnSCMP{Error: true, HopByHop: true}),
				revScmpHdrPld,
			}},
		Out: []*layers.ExpPkt{
			{Dev: "ifid_local", Layers: []layers.LayerMatcher{
				layers.GenOverlayIP4UDP("192.168.0.14", 30004, "192.168.0.71", 30041),
				revScionHdr,
				&layers.ScionSCMPExtn{ExtnSCMP: layers.ExtnSCMP{Error: true, HopByHop: true}},
				revScmpHdrPld,
			}},
			{Dev: "ifid_local", Layers: []layers.LayerMatcher{
				layers.GenOverlayIP4UDP("192.168.0.14", 30041, "192.168.0.51", 30041),
				revPsScionHdr,
				layers.NewUDP(20004, 0, &revPsScionHdr.ScionLayer, revPsPld),
				revPsPld,
			}}},
		Ignore: IgnoredPacketsBrD,
	}
	tests = append(tests, revLocalFork)
	// We use a known IP ie. CS, so we already have ARP entry for it
	revScionHdr = layers.NewGenCmnHdr("1-ff00:0:7", "172.16.7.1", "1-ff00:0:5", "172.16.5.1",
		layers.GenPath(0, 1, layers.Segments{
			segment("(C__)[0.711][171.151][511.0]", hMac, 1)},
		),
		common.HopByHopClass)

	sRevInfo = layers.MustSRevInfo(777, "1-ff00:0:7", "child", tsNow32, 10)
	rev = layers.NewRevocation(0, 1, 777, false, sRevInfo)

	revScmpHdrPld = layers.NewSCMP(scmp.C_Path, scmp.T_P_RevokedIF, now,
		&revScionHdr.ScionLayer, []layers.LayerBuilder{
			layers.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:9", "172.16.9.1",
				layers.GenPath(0, 1, layers.Segments{
					segment("(___)[511.0][171.151][0.711]", hMac, 1)},
				), nil,
				&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil)},
		rev,
		common.L4UDP)

	revPsScionHdr = layers.NewGenCmnHdr("1-ff00:0:1", "192.168.0.104", "1-ff00:0:1", "PS",
		nil, common.L4UDP)
	revBsScionHdr := layers.NewGenCmnHdr("1-ff00:0:1", "192.168.0.104", "1-ff00:0:1", "BS",
		nil, common.L4UDP)
	revPsPld = &layers.PathMgmtPld{
		Signer:      infra.NullSigner,
		SigVerifier: infra.NullSigVerifier,
		Instance:    sRevInfo,
	}

	revLocalFork = &BRTest{
		Desc:    "Multiple IFIDs - Local ISD revocation on parent ifid, fork to PS and BS",
		Timeout: 1 * time.Second, // Control packets need to go through the dispatcher
		In: &layers.Pkt{
			Dev: "ifid_171", Layers: []layers.LayerBuilder{
				layers.GenOverlayIP4UDP("192.168.17.3", 40000, "192.168.17.2", 50000),
				revScionHdr,
				layers.NewSCMPExtn(common.L4SCMP, layers.ExtnSCMP{Error: true, HopByHop: true}),
				revScmpHdrPld,
			}},
		Out: []*layers.ExpPkt{
			{Dev: "ifid_151", Layers: []layers.LayerMatcher{
				layers.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
				layers.NewGenCmnHdr("1-ff00:0:7", "172.16.7.1", "1-ff00:0:5", "172.16.5.1",
					layers.GenPath(0, 2, layers.Segments{
						segment("(C__)[0.711][171.151][511.0]", hMac, 1)},
					),
					common.HopByHopClass),
				&layers.ScionSCMPExtn{ExtnSCMP: layers.ExtnSCMP{Error: true, HopByHop: true}},
				revScmpHdrPld,
			}},
			{Dev: "ifid_local", Layers: []layers.LayerMatcher{
				layers.GenOverlayIP4UDP("192.168.0.14", 30041, "192.168.0.51", 30041),
				revPsScionHdr,
				layers.NewUDP(20004, 0, &revPsScionHdr.ScionLayer, revPsPld),
				revPsPld,
			}},
			{Dev: "ifid_local", Layers: []layers.LayerMatcher{
				layers.GenOverlayIP4UDP("192.168.0.14", 30041, "192.168.0.61", 30041),
				revBsScionHdr,
				layers.NewUDP(20004, 0, &revBsScionHdr.ScionLayer, revPsPld),
				revPsPld,
			}}},
		Ignore: IgnoredPacketsBrD,
	}
	tests = append(tests, revLocalFork)
	// We use a known IP ie. CS, so we already have ARP entry for it
	revScionHdr = layers.NewGenCmnHdr("2-ff00:0:7", "172.16.7.1", "1-ff00:0:5", "172.16.5.1",
		layers.GenPath(0, 1, layers.Segments{
			segment("(C__)[0.711][171.151][511.0]", hMac, 1)},
		),
		common.HopByHopClass)

	revScmpHdrPld = layers.NewSCMP(scmp.C_Path, scmp.T_P_RevokedIF, now,
		&revScionHdr.ScionLayer, []layers.LayerBuilder{
			layers.NewValidScion("1-ff00:0:5", "172.16.5.1", "2-ff00:0:9", "172.16.9.1",
				layers.GenPath(0, 1, layers.Segments{
					segment("(___)[511.0][171.151][0.711]", hMac, 1)},
				), nil,
				&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil)},
		layers.NewRevocation(0, 1, 777, false,
			layers.MustSRevInfo(777, "2-ff00:0:7", "child", tsNow32, 10)),
		common.L4UDP)

	revLocalFork = &BRTest{
		Desc: "Multiple IFIDs - Revocation from remote ISD, just forward",
		In: &layers.Pkt{
			Dev: "ifid_171", Layers: []layers.LayerBuilder{
				layers.GenOverlayIP4UDP("192.168.17.3", 40000, "192.168.17.2", 50000),
				revScionHdr,
				layers.NewSCMPExtn(common.L4SCMP, layers.ExtnSCMP{Error: true, HopByHop: true}),
				revScmpHdrPld,
			}},
		Out: []*layers.ExpPkt{
			{Dev: "ifid_151", Layers: []layers.LayerMatcher{
				layers.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
				layers.NewGenCmnHdr("2-ff00:0:7", "172.16.7.1", "1-ff00:0:5", "172.16.5.1",
					layers.GenPath(0, 2, layers.Segments{
						segment("(C__)[0.711][171.151][511.0]", hMac, 1)},
					),
					common.HopByHopClass),
				&layers.ScionSCMPExtn{ExtnSCMP: layers.ExtnSCMP{Error: true, HopByHop: true}},
				revScmpHdrPld,
			}}},
		Ignore: IgnoredPacketsBrD,
	}
	tests = append(tests, revLocalFork)
	pktTriggerRev := layers.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:6", "172.16.6.1",
		layers.GenPath(0, 1, layers.Segments{
			segment("(___)[511.0][161.151][0.611]", hMac, 1)},
		), nil,
		&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil)

	revScmpScionHdr := layers.NewGenCmnHdr("1-ff00:0:1", "192.168.0.14", "1-ff00:0:5", "172.16.5.1",
		layers.GenPath(0, 2, layers.Segments{
			segment("(C__)[0.611][161.151][511.0]", hMac, 1)},
		),
		common.HopByHopClass)

	brCtrlScionHdr := layers.NewGenCmnHdr(
		"1-ff00:0:1", "192.168.0.61", "1-ff00:0:1", "192.168.0.104", nil, common.L4UDP)

	signedRevInfo := layers.MustSRevInfo(161, "1-ff00:0:1", "parent", tsNow32, 60)

	ifStateInfoDown := &layers.PathMgmtPld{
		Signer:      infra.NullSigner,
		SigVerifier: infra.NullSigVerifier,
		Instance: &path_mgmt.IFStateInfos{Infos: []*path_mgmt.IFStateInfo{
			{IfID: 161, Active: false, SRevInfo: signedRevInfo},
		}},
	}
	ifStateInfoUp := &layers.PathMgmtPld{
		Signer:      infra.NullSigner,
		SigVerifier: infra.NullSigVerifier,
		Instance: &path_mgmt.IFStateInfos{Infos: []*path_mgmt.IFStateInfo{
			{IfID: 161, Active: true, SRevInfo: nil},
		}},
	}
	revTest := &BRTest{
		Desc: "Multiple IFIDs - Revocation on interface not owned",
		Pre: &layers.Pkt{
			Dev: "ifid_local", Layers: []layers.LayerBuilder{
				layers.GenOverlayIP4UDP("192.168.0.61", 20006, "192.168.0.14", 30041),
				brCtrlScionHdr,
				layers.NewUDP(20006, 20004, &brCtrlScionHdr.ScionLayer, ifStateInfoDown),
				ifStateInfoDown,
			}},
		In: &layers.Pkt{
			Dev: "ifid_151", Layers: []layers.LayerBuilder{
				layers.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
				pktTriggerRev,
			}},
		Out: []*layers.ExpPkt{
			{Dev: "ifid_151", Layers: []layers.LayerMatcher{
				layers.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
				revScmpScionHdr,
				&layers.ScionSCMPExtn{ExtnSCMP: layers.ExtnSCMP{Error: true, HopByHop: true}},
				layers.NewSCMP(scmp.C_Path, scmp.T_P_RevokedIF, noTime,
					&revScmpScionHdr.ScionLayer,
					[]layers.LayerBuilder{
						pktTriggerRev,
					},
					layers.NewRevocation(0, 1, 161, true, signedRevInfo),
					common.L4UDP),
			}}},
		Post: &layers.Pkt{
			Dev: "ifid_local", Layers: []layers.LayerBuilder{
				layers.GenOverlayIP4UDP("192.168.0.61", 20006, "192.168.0.14", 30041),
				brCtrlScionHdr,
				layers.NewUDP(20006, 20004, &brCtrlScionHdr.ScionLayer, ifStateInfoUp),
				ifStateInfoUp,
			}},
		Ignore: IgnoredPacketsBrD,
	}
	tests = append(tests, revTest)
	return tests
}
