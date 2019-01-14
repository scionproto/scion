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
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
)

var brDCtrlScionHdr = tpkt.NewGenCmnHdr(
	"1-ff00:0:1", "192.168.0.104", "1-ff00:0:1", "BS_M", nil, common.L4UDP)

var IgnoredPacketsBrD = []*tpkt.ExpPkt{
	{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
		tpkt.GenOverlayIP4UDP("192.168.0.14", 30041, "192.168.0.61", 30041),
		brDCtrlScionHdr,
		tpkt.NewUDP(20004, 0, &brDCtrlScionHdr.ScionLayer, ifStateReq),
		ifStateReq,
	}}}

func genTestsBrD(hMac hash.Hash) []*BRTest {
	tests := []*BRTest{
		{
			Desc: "Multiple IFIDs - child/local",
			In: &tpkt.Pkt{
				Dev: "ifid_151", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.4.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[511.0][0.151]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.14", 30004, "192.168.0.51", 30041),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.4.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[511.0][0.151]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrD,
		},
		{
			Desc: "Multiple IFIDs - local/child",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.14", 30004),
					tpkt.NewValidScion("1-ff00:0:1", "192.168.0.51", "1-ff00:0:5", "172.16.4.1",
						tpkt.GenPath(0, 0, tpkt.Segments{
							segment("(C__)[0.151][511.0]", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_151", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:5", "172.16.4.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.151][511.0]", hMac, 0)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrD,
		},
		{
			Desc: "Multiple IFIDs - child/parent",
			In: &tpkt.Pkt{
				Dev: "ifid_151", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.4.1", "1-ff00:0:6", "172.16.6.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[511.0][162.151][0.612]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_162", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.16.4", 50000, "192.168.16.5", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.4.1", "1-ff00:0:6", "172.16.6.1",
						tpkt.GenPath(0, 2, tpkt.Segments{
							segment("(___)[511.0][162.151][0.612]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrD,
		},
		{
			Desc: "Multiple IFIDs - parent/child",
			In: &tpkt.Pkt{
				Dev: "ifid_162", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.16.5", 40000, "192.168.16.4", 50000),
					tpkt.NewValidScion("1-ff00:0:6", "172.16.6.1", "1-ff00:0:5", "172.16.4.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.612][162.151][511.0]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_151", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:6", "172.16.6.1", "1-ff00:0:5", "172.16.4.1",
						tpkt.GenPath(0, 2, tpkt.Segments{
							segment("(C__)[0.612][162.151][511.0]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrD,
		},
		{
			Desc: "Multiple IFIDs - Xover child/peer",
			In: &tpkt.Pkt{
				Dev: "ifid_151", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(_SP)[511.0][X.162.151][X.131.151][V.0.612]", hMac, 1, 2),
							segment("(C__)[V.0.831][X.311.0][X.381.0]", nil)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_131", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.13.2", 50000, "192.168.13.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							segment("(_SP)[511.0][X.162.151][X.131.151][V.0.612]", hMac, 1, 2),
							segment("(C__)[V.0.831][X.311.0][X.381.0]", nil)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrD,
		},
		{
			Desc: "Multiple IFIDs - Xover peer/child",
			In: &tpkt.Pkt{
				Dev: "ifid_131", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.13.3", 40000, "192.168.13.2", 50000),
					tpkt.NewValidScion("1-ff00:0:3", "173.16.3.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							segment("(_SP)[X.381.0][X.311.0][V.0.831]", nil),
							segment("(CSP)[V.0.612][X.131.151][X.162.151][511.0]", hMac, 1, 2)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_151", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:3", "173.16.3.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 3, tpkt.Segments{
							segment("(_SP)[X.381.0][X.311.0][V.0.831]", nil),
							segment("(CSP)[V.0.612][X.131.151][X.162.151][511.0]", hMac, 1, 2)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrD,
		},
		{
			Desc: "Multiple IFIDs - Xover child/child",
			In: &tpkt.Pkt{
				Dev: "ifid_142", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.14.5", 40000, "192.168.14.4", 50000),
					tpkt.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(_S_)[412.0][X.162.142][V.0.612]", hMac, 1),
							segment("(CS_)[V.0.612][X.162.151][511.0]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_151", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 2, tpkt.Segments{
							segment("(_S_)[412.0][X.162.142][V.0.612]", hMac, 1),
							segment("(CS_)[V.0.612][X.162.151][511.0]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrD,
		},
	}
	// We use a known IP ie. CS, so we already have ARP entry for it
	revScionHdr := tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:1", "192.168.0.71",
		tpkt.GenPath(0, 2, tpkt.Segments{
			segment("(___)[999.0][511.512][0.151]", hMac, 2)},
		),
		common.HopByHopClass)

	sRevInfo := tpkt.MustSRevInfo(512, "1-ff00:0:5", "child", tsNow32, 60)
	rev := tpkt.NewRevocation(0, 1, 512, false, sRevInfo)

	revScmpHdrPld := tpkt.NewSCMP(scmp.C_Path, scmp.T_P_RevokedIF, now,
		&revScionHdr.ScionLayer, []tpkt.LayerBuilder{
			tpkt.NewValidScion("1-ff00:0:1", "192.168.0.71", "1-ff00:0:9", "172.16.9.1",
				tpkt.GenPath(0, 1, tpkt.Segments{
					segment("(C__)[0.151][511.512][999.0]", hMac, 0)},
				), nil,
				&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil)},
		rev,
		common.L4UDP)

	revPsScionHdr := tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.104", "1-ff00:0:1", "PS",
		nil, common.L4UDP)
	revPsPld := &tpkt.PathMgmtPld{
		Signer:      ctrl.NullSigner,
		SigVerifier: ctrl.NullSigVerifier,
		Instance:    sRevInfo,
	}

	revLocalFork := &BRTest{
		Desc: "Multiple IFIDs - Revocation to local destination, fork to PS",
		In: &tpkt.Pkt{
			Dev: "ifid_151", Layers: []tpkt.LayerBuilder{
				tpkt.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
				revScionHdr,
				tpkt.NewSCMPExtn(common.L4SCMP, scmp.Extn{Error: true, HopByHop: true}),
				revScmpHdrPld,
			}},
		Out: []*tpkt.ExpPkt{
			{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
				tpkt.GenOverlayIP4UDP("192.168.0.14", 30004, "192.168.0.71", 30041),
				revScionHdr,
				&tpkt.ScionSCMPExtn{Extn: scmp.Extn{Error: true, HopByHop: true}},
				revScmpHdrPld,
			}},
			{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
				tpkt.GenOverlayIP4UDP("192.168.0.14", 30041, "192.168.0.51", 30041),
				revPsScionHdr,
				tpkt.NewUDP(20004, 0, &revPsScionHdr.ScionLayer, revPsPld),
				revPsPld,
			}}},
		Ignore: IgnoredPacketsBrD,
	}
	tests = append(tests, revLocalFork)
	return tests
}
