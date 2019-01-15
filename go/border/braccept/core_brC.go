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
)

var coreBrCCtrlScionHdr = tpkt.NewGenCmnHdr(
	"1-ff00:0:1", "192.168.0.103", "1-ff00:0:1", "BS_M", nil, common.L4UDP)

var IgnoredPacketsCoreBrC = []*tpkt.ExpPkt{
	{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
		tpkt.GenOverlayIP4UDP("192.168.0.13", 30041, "192.168.0.61", 30041),
		coreBrCCtrlScionHdr,
		tpkt.NewUDP(20003, 0, &coreBrCCtrlScionHdr.ScionLayer, ifStateReq),
		ifStateReq,
	}}}

func genTestsCoreBrC(hMac hash.Hash) []*BRTest {
	return []*BRTest{
		{
			Desc: "Multiple IFIDs - core/local",
			In: &tpkt.Pkt{
				Dev: "ifid_131", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.13.3", 40000, "192.168.13.2", 50000),
					tpkt.NewValidScion("1-ff00:0:3", "172.16.3.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.311][131.0]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.13", 30003, "192.168.0.51", 30041),
					tpkt.NewGenCmnHdr("1-ff00:0:3", "172.16.3.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.311][131.0]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsCoreBrC,
		},
		{
			Desc: "Multiple IFIDs - local/core",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.13", 30003),
					tpkt.NewValidScion("1-ff00:0:1", "192.168.0.51", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 0, tpkt.Segments{
							segment("(___)[131.0][0.311]", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_131", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.13.2", 50000, "192.168.13.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[131.0][0.311]", hMac, 0)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsCoreBrC,
		},
		{
			Desc: "Multiple IFIDs - core/core - external",
			In: &tpkt.Pkt{
				Dev: "ifid_122", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.5", 40000, "192.168.12.4", 50000),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[212.0][131.122][0.311]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_131", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.13.2", 50000, "192.168.13.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 2, tpkt.Segments{
							segment("(___)[212.0][131.122][0.311]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsCoreBrC,
		},
		{
			Desc: "Multiple IFIDs - core/core - internal",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.11", 30003, "192.168.0.13", 30003),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[211.0][131.121][0.311]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_131", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.13.2", 50000, "192.168.13.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 2, tpkt.Segments{
							segment("(___)[211.0][131.121][0.311]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsCoreBrC,
		},
		{
			Desc: "Multiple IFIDs - Xover core/child",
			In: &tpkt.Pkt{
				Dev: "ifid_131", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.13.3", 40000, "192.168.13.2", 50000),
					tpkt.NewValidScion("1-ff00:0:3", "172.16.3.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[311.0][X_.0.131]", hMac, 1),
							segment("(C__)[0.151][511.0]", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_151", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:3", "172.16.3.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							segment("(___)[311.0][X_.0.131]", hMac, 1),
							segment("(C__)[0.151][511.0]", hMac, 0)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsCoreBrC,
		},
		{
			Desc: "Multiple IFIDs - Xover child/core",
			In: &tpkt.Pkt{
				Dev: "ifid_151", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[511.0][X_.0.151]", hMac, 1),
							segment("(C__)[0.131][311.0]", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_131", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.13.2", 50000, "192.168.13.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							segment("(___)[511.0][X_.0.151]", hMac, 1),
							segment("(C__)[0.131][311.0]", hMac, 0)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsCoreBrC,
		},
		{
			Desc: "Multiple IFIDs - Xover child/child",
			In: &tpkt.Pkt{
				Dev: "ifid_151", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[511.0][X_.0.151]", hMac, 1),
							segment("(C__)[0.142][412.0]", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_142", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.14.4", 50000, "192.168.14.5", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							segment("(___)[511.0][X_.0.151]", hMac, 1),
							segment("(C__)[0.142][412.0]", hMac, 0)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsCoreBrC,
		},
		/* TODO(sgmonroy) uncomment once BR drops packets entering/leaving through the same ifid
		{
			Desc: "Multiple IFIDs core - external - Xover child/child - same ingress/egress ifid",
			In: &tpkt.Pkt{
				Dev: "ifid_151", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:5", "172.16.5.2",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[511.0][X_.0.151]", hMac, 1),
							segment("(C__)[0.151][511.0]", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{},
			Ignore: IgnoredPacketsCoreBrC,
		},
		// TODO(sgmonroy) uncomment once BR drops packets coming from and destined to the same AS
		{
			Desc: "Multiple IFIDs core - external - Xover child/child - same ingress/egress AS",
			In: &tpkt.Pkt{
				Dev: "ifid_151", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:5", "172.16.5.2",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[511.0][X_.0.151]", hMac, 1),
							segment("(C__)[0.152][512.0]", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{},
			Ignore: IgnoredPacketsCoreBrC,
		},
		*/
	}
}
