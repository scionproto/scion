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
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/l4"
	//"github.com/scionproto/scion/go/lib/scmp"
)

var IgnoredPacketsBrA = []*tpkt.ExpPkt{
	{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
		tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.61", 30041),
		tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.11", "1-ff00:0:1", "SVC_M",
			nil, common.L4UDP),
		&tpkt.PathMgmtPld{SigVerifier: ctrl.NullSigVerifier, Instance: &path_mgmt.IFStateReq{}},
	}}}

func genTestsBrA(hMac hash.Hash) []*BRTest {
	return []*BRTest{
		{
			Desc: "Single IFID Peer - external - local destination",
			In: &tpkt.Pkt{
				Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(1, 1, tpkt.Segments{
							revsegP_2C0X_2A0X_06C,
							seg_06A_1A0X_1C0X.Macs(hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.51", 30041),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(1, 1, tpkt.Segments{
							revsegP_2C0X_2A0X_06C,
							seg_06A_1A0X_1C0X.Macs(hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Single IFID Peer - internal - remote destination",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.11", 30001),
					tpkt.NewValidScion("1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							revsegSP_1C0X_1A0X_06AV.Macs(hMac, 0, 1),
							seg_06CV_2A0X_2C0X},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							revsegSP_1C0X_1A0X_06AV.Macs(hMac, 0, 1),
							seg_06CV_2A0X_2C0X},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Single IFID Peer - internal - remote destination",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.11", 30001),
					tpkt.NewValidScion("1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							revsegSP_1C0X_1A0X_06AV.Macs(hMac, 0),
							seg_06CV_2A0X_2C0X},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							revsegSP_1C0X_1A0X_06AV.Macs(hMac, 0, 1),
							seg_06CV_2A0X_2C0X},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		/*
			{
				Desc: "Single IFID Peer - external - Xover core/child",
				In: &tpkt.Pkt{
					Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
						tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
						tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1",
							tpkt.GenPath(1, 2,
								path_2A_1A_X_1C_5A.SetMac(1, 2, hMac).SetMac(2, 1, hMac)), nil,
							&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
					}},
				Out: []*tpkt.ExpPkt{
					{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
						tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.13", 30003),
						tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1",
							tpkt.GenPath(2, 1,
								path_2A_1A_X_1C_5A.SetMac(1, 2, hMac).SetMac(2, 1, hMac)),
							common.L4UDP),
						tpkt.NewUDP(40111, 40222, nil),
					}}},
			},
			{
				Desc: "Single IFID Peer - internal - Xover child/core",
				In: &tpkt.Pkt{
					Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
						tpkt.GenOverlayIP4UDP("192.168.0.13", 30003, "192.168.0.11", 30001),
						tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1",
							tpkt.GenPath(2, 1,
								path_5A_1C_X_1A_2A.SetMac(1, 2, hMac).SetMac(2, 1, hMac)), nil,
							&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
					}},
				Out: []*tpkt.ExpPkt{
					{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
						tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
						tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1",
							tpkt.GenPath(2, 2,
								path_5A_1C_X_1A_2A.SetMac(1, 2, hMac).SetMac(2, 1, hMac)),
							common.L4UDP),
						tpkt.NewUDP(40111, 40222, nil),
					}}},
			},
			{
				Desc: "Single IFID - external - bad path - Xover peer-core",
				In: &tpkt.Pkt{
					Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
						tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
						tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
							tpkt.GenPath(1, 2, path_2A_1A_X_1C_3A.SetMac(1, 1, hMac)), nil,
							&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
					}},
				Out: []*tpkt.ExpPkt{
					{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
						tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 50001),
						tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.11", "1-ff00:0:2", "172.16.2.1",
							tpkt.GenPath(2, 2, path_2A_1A_X_1C_3A_rev.SetMac(1, 1, hMac)),
							common.HopByHopClass),
						&tpkt.ScionHBHSCMP{Extn: scmp.Extn{Error: true}},
						tpkt.NewSCMP(scmp.C_Path, scmp.T_P_BadSegment, []tpkt.LayerBuilder{
							tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
								tpkt.GenPath(2, 1, path_2A_1A_X_1C_3A.SetMac(1, 1, hMac)), nil,
								&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil)},
							tpkt.NewInfoPathOffsets(if_121, true),
							common.L4UDP),
					}}},
			},
			{
				Desc: "Single IFID - external - bad path - Xover peer-core unsupported l4",
				In: &tpkt.Pkt{
					Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
						tpkt.GenOverlayIP4UDP("192.168.12.3", 50001, "192.168.12.2", 50000),
						tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
							tpkt.GenPath(1, 2, path_2A_1A_X_1C_3A.SetMac(1, 1, hMac)),
							common.L4TCP),
						tpkt.NewPld([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
					}},
				Out: []*tpkt.ExpPkt{
					{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
						tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 50001),
						tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.11", "1-ff00:0:2", "172.16.2.1",
							tpkt.GenPath(2, 2, path_2A_1A_X_1C_3A_rev.SetMac(1, 1, hMac)),
							common.HopByHopClass),
						&tpkt.ScionHBHSCMP{Extn: scmp.Extn{Error: true}},
						tpkt.NewSCMP(scmp.C_Path, scmp.T_P_BadSegment, []tpkt.LayerBuilder{
							tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
								tpkt.GenPath(2, 1, path_2A_1A_X_1C_3A.SetMac(1, 1, hMac)),
								common.L4TCP),
							tpkt.NewPld([]byte{1, 2, 3, 4, 5, 6, 7, 8})},
							tpkt.NewInfoPathOffsets(if_121, true),
							common.L4TCP),
					}}},
			},
			{
				Desc: "Single IFID - external - empty overlay packet",
				In: &tpkt.Pkt{
					Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
						tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
					}},
				Out: []*tpkt.ExpPkt{},
			},
			{
				Desc: "Single IFID - external - bad packet 7 Bytes",
				In: &tpkt.Pkt{
					Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
						tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
						tpkt.NewPld([]byte{1, 2, 3, 4, 5, 6, 7}),
					}},
				Out: []*tpkt.ExpPkt{},
			},
		*/
	}
}
