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

var brCCtrlScionHdr = tpkt.NewGenCmnHdr(
	"1-ff00:0:1", "192.168.0.103", "1-ff00:0:1", "BS_M", nil, common.L4UDP)

var IgnoredPacketsBrC = []*tpkt.ExpPkt{
	{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
		tpkt.GenOverlayIP4UDP("192.168.0.13", 30041, "192.168.0.61", 30041),
		brCCtrlScionHdr,
		tpkt.NewUDP(20003, 0, &brCCtrlScionHdr.ScionLayer, ifStateReq),
		ifStateReq,
	}}}

func genTestsBrC(hMac hash.Hash) []*BRTest {
	return []*BRTest{
		{
			Desc: "Single IFID parent - parent/local",
			In: &tpkt.Pkt{
				Dev: "ifid_161", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.16.3", 40000, "192.168.16.2", 50000),
					tpkt.NewValidScion("1-ff00:0:6", "172.16.6.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[611.0][0.161]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.13", 30003, "192.168.0.51", 30041),
					tpkt.NewGenCmnHdr("1-ff00:0:6", "172.16.6.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[611.0][0.161]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrC,
		},
		{
			Desc: "Single IFID parent - local/parent",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.13", 30003),
					tpkt.NewValidScion("1-ff00:0:1", "192.168.0.51", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(0, 0, tpkt.Segments{
							segment("(C__)[0.161][611.0]", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_161", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.16.2", 50000, "192.168.16.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.161][611.0]", hMac, 0)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrC,
		},
		{
			Desc: "Single IFID parent - parent/child",
			In: &tpkt.Pkt{
				Dev: "ifid_161", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.16.3", 40000, "192.168.16.2", 50000),
					tpkt.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:6", "172.16.6.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.611][161.141][411.0]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.13", 30003, "192.168.0.12", 30002),
					tpkt.NewGenCmnHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:6", "172.16.6.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.611][161.141][411.0]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrC,
		},
		{
			Desc: "Single IFID parent - child/parent",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.12", 30002, "192.168.0.13", 30003),
					tpkt.NewValidScion("1-ff00:0:6", "172.16.6.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(___)[411.0][161.141][0.611]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_161", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.16.2", 50000, "192.168.16.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:6", "172.16.6.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(0, 2, tpkt.Segments{
							segment("(___)[411.0][161.141][0.611]", hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrC,
		},
	}
}
