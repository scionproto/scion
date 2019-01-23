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

var brBCtrlScionHdr = tpkt.NewGenCmnHdr(
	"1-ff00:0:1", "192.168.0.102", "1-ff00:0:1", "BS_M", nil, common.L4UDP)

var IgnoredPacketsBrB = []*tpkt.ExpPkt{
	{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
		tpkt.GenOverlayIP4UDP("192.168.0.12", 30041, "192.168.0.61", 30041),
		brBCtrlScionHdr,
		tpkt.NewUDP(20002, 0, &brBCtrlScionHdr.ScionLayer, ifStateReq),
		ifStateReq,
	}}}

func genTestsBrB(hMac hash.Hash) []*BRTest {
	return []*BRTest{
		{
			Desc: "Single IFID child - child/local",
			In: &tpkt.Pkt{
				Dev: "ifid_141", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
					tpkt.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[411.0][0.141]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.12", 30002, "192.168.0.51", 30041),
					tpkt.NewGenCmnHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[411.0][0.141]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
		{
			Desc: "Single IFID child - local/child",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.12", 30002),
					tpkt.NewValidScion("1-ff00:0:1", "192.168.0.51", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(0, 0, tpkt.Segments{
							segment("(C__)[0.141][411.0]", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_141", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.14.2", 50000, "192.168.14.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.141][411.0]", hMac, 0)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
		{
			Desc: "Single IFID child - child/parent",
			In: &tpkt.Pkt{
				Dev: "ifid_141", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
					tpkt.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:6", "172.16.6.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[411.0][162.141][0.612]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.12", 30002, "192.168.0.14", 30004),
					tpkt.NewGenCmnHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:6", "172.16.6.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[411.0][162.141][0.612]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
		{
			Desc: "Single IFID child - parent/child",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.14", 30004, "192.168.0.12", 30002),
					tpkt.NewValidScion("1-ff00:0:6", "172.16.6.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.612][162.141][411.0]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_141", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.14.2", 50000, "192.168.14.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:6", "172.16.6.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(0, 2, tpkt.Segments{
							segment("(C__)[0.612][162.141][411.0]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
		{
			Desc: "Single IFID child - Xover child/peer",
			In: &tpkt.Pkt{
				Dev: "ifid_141", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
					tpkt.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(_SP)[411.0][X_.161.141][X_.121.141][_V.0.611]", hMac, 1, 2),
							segment("(C__)[_V.0.621][X_.211.0][X_.261.0]", nil)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.12", 30002, "192.168.0.11", 30001),
					tpkt.NewGenCmnHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(0, 2, tpkt.Segments{
							segment("(_SP)[411.0][X_.161.141][X_.121.141][_V.0.611]", hMac, 1, 2),
							segment("(C__)[_V.0.621][X_.211.0][X_.261.0]", nil)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
		{
			Desc: "Single IFID child - Xover peer/child",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.12", 30002),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(1, 2, tpkt.Segments{
							segment("(__P)[X_.261.0][X_.211.0][0.621]", nil),
							segment("(CSP)[0.611][X_.121.141][X_.161.141][411.0]", hMac, 1, 2)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_141", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.14.2", 50000, "192.168.14.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(1, 3, tpkt.Segments{
							segment("(__P)[X_.261.0][X_.211.0][0.621]", nil),
							segment("(CSP)[0.611][X_.121.141][X_.161.141][411.0]", hMac, 1, 2)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
		{
			Desc: "Single IFID child - Xover child/child - external",
			In: &tpkt.Pkt{
				Dev: "ifid_141", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
					tpkt.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(_S_)[411.0][X_.162.141][_V.0.612]", hMac, 1),
							segment("(CS_)[_V.0.612][X_.162.151][511.0]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.12", 30002, "192.168.0.14", 30004),
					tpkt.NewGenCmnHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							segment("(_S_)[411.0][X_.162.141][_V.0.612]", hMac, 1),
							segment("(CS_)[_V.0.612][X_.162.151][511.0]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
		{
			Desc: "Single IFID child - Xover child/child - internal",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.14", 30004, "192.168.0.12", 30002),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							segment("(_S_)[511.0][X_.162.151][_V.0.612]", hMac, 1),
							segment("(CS_)[_V.0.612][X_.162.141][411.0]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_141", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.14.2", 50000, "192.168.14.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(1, 2, tpkt.Segments{
							segment("(_S_)[511.0][X_.162.151][_V.0.612]", hMac, 1),
							segment("(CS_)[_V.0.612][X_.162.141][411.0]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
	}
}
