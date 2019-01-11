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
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
)

var coreBrACtrlScionHdr = tpkt.NewGenCmnHdr(
	"1-ff00:0:1", "192.168.0.101", "1-ff00:0:1", "BS_M", nil, common.L4UDP)

var IgnoredPacketsCoreBrA = []*tpkt.ExpPkt{
	{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
		tpkt.GenOverlayIP4UDP("192.168.0.11", 30041, "192.168.0.61", 30041),
		coreBrACtrlScionHdr,
		tpkt.NewUDP(20001, 0, &coreBrACtrlScionHdr.ScionLayer, ifStateReq),
		ifStateReq,
	}}}

func genTestsCoreBrA(hMac hash.Hash) []*BRTest {
	return []*BRTest{
		{
			Desc: "Single IFID core - external - local destination",
			In: &tpkt.Pkt{
				Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.211 121.0", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.51", 30041),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.211 121.0", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsCoreBrA,
		},
		{
			Desc: "Single IFID core - internal - remote destination",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.11", 30001),
					tpkt.NewValidScion("1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(0, 0, tpkt.Segments{
							segment("(C__)[0.121 211.0", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.121 211.0", hMac, 0)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsCoreBrA,
		},
		{
			Desc: "Single IFID core - Xover core/child",
			In: &tpkt.Pkt{
				Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.211 X.121.0", hMac, 1),
							segment("(C__)[0.141 411.0", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.12", 30002),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 0, tpkt.Segments{
							segment("(C__)[0.211 X.121.0", hMac, 1),
							segment("(C__)[0.141 411.0", hMac, 0)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsCoreBrA,
		},
		{
			Desc: "Single IFID core - Xover child/core",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.13", 30003, "192.168.0.11", 30001),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(1, 0, tpkt.Segments{
							segment("(___)[411.0 X.0.141", hMac, 1),
							segment("(___)[121.0 0.211", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							segment("(___)[411.0 X.0.141", hMac, 1),
							segment("(___)[121.0 0.211", hMac, 0)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsCoreBrA,
		},
		{
			Desc: "Single IFID core - Xover core-core - Bad Path",
			In: &tpkt.Pkt{
				Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.211 X.121.0", hMac, 1),
							segment("(C__)[0.131 311.0", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.11", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(1, 0, tpkt.Segments{
							segment("(___)[311.0 0.131", hMac, 1),
							segment("(___)[X.121.0 0.211", hMac, 0)},
						),
						common.HopByHopClass),
					&tpkt.ScionSCMPExtn{Extn: scmp.Extn{Error: true}},
					tpkt.NewSCMP(scmp.C_Path, scmp.T_P_BadSegment, []tpkt.LayerBuilder{
						tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
							tpkt.GenPath(1, 0, tpkt.Segments{
								segment("(C__)[0.211 X.121.0", hMac, 1),
								segment("(C__)[0.131 311.0", hMac, 0)},
							), nil,
							&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil)},
						&scmp.InfoPathOffsets{InfoF: 1, HopF: 0, IfID: if_121, Ingress: true},
						common.L4UDP),
				}}},
			Ignore: IgnoredPacketsCoreBrA,
		},
		{
			Desc: "Single IFID core - Xover core-core - Bad Path Unsupported L4",
			In: &tpkt.Pkt{
				Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.211 X.121.0", hMac, 1),
							segment("(C__)[0.131 311.0", hMac, 0)},
						),
						common.L4TCP),
					tpkt.NewPld([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.11", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(1, 0, tpkt.Segments{
							segment("(___)[311.0 0.131", hMac, 1),
							segment("(___)[X.121.0 0.211", hMac, 0)},
						),
						common.HopByHopClass),
					&tpkt.ScionSCMPExtn{Extn: scmp.Extn{Error: true}},
					tpkt.NewSCMP(scmp.C_Path, scmp.T_P_BadSegment, []tpkt.LayerBuilder{
						tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
							tpkt.GenPath(1, 0, tpkt.Segments{
								segment("(C__)[0.211 X.121.0", hMac, 1),
								segment("(C__)[0.131 311.0", hMac, 0)},
							),
							common.L4TCP),
						tpkt.NewPld([]byte{1, 2, 3, 4, 5, 6, 7, 8})},
						&scmp.InfoPathOffsets{InfoF: 1, HopF: 0, IfID: if_121, Ingress: true},
						common.L4TCP),
				}}},
			Ignore: IgnoredPacketsCoreBrA,
		},
		{
			Desc: "Single IFID core - Empty overlay packet",
			In: &tpkt.Pkt{
				Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
				}},
			Out:    []*tpkt.ExpPkt{},
			Ignore: IgnoredPacketsCoreBrA,
		},
		{
			Desc: "Single IFID core - Bad packet 7 Bytes",
			In: &tpkt.Pkt{
				Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
					tpkt.NewPld([]byte{1, 2, 3, 4, 5, 6, 7}),
				}},
			Out:    []*tpkt.ExpPkt{},
			Ignore: IgnoredPacketsCoreBrA,
		},
	}
}
