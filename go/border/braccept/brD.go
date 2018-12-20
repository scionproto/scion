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

var IgnoredPacketsBrD = []*tpkt.ExpPkt{
	{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
		tpkt.GenOverlayIP4UDP("192.168.0.14", 30041, "192.168.0.61", 30041),
		tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.104", "1-ff00:0:1", "BS_M", nil, common.L4UDP),
		tpkt.NewUDP(20004, 0, ifStateReq),
		ifStateReq,
	}}}

func genTestsBrD(hMac hash.Hash) []*BRTest {
	return []*BRTest{
		{
			Desc: "Multiple IFIDs - child/local",
			In: &tpkt.Pkt{
				Dev: "ifid_151", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.4.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, tpkt.Segments{
							revseg_5A0_01C.Macs(hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.14", 30004, "192.168.0.51", 30041),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.4.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, tpkt.Segments{
							revseg_5A0_01C.Macs(hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
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
							seg_01C_5A0.Macs(hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_151", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:5", "172.16.4.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							seg_01C_5A0.Macs(hMac, 0)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
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
							revseg_5A0_1D1D_06B.Macs(hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_162", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.16.4", 50000, "192.168.16.5", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.4.1", "1-ff00:0:6", "172.16.6.1",
						tpkt.GenPath(0, 2, tpkt.Segments{
							revseg_5A0_1D1D_06B.Macs(hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
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
							seg_06B_1D1D_5A0.Macs(hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_151", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:6", "172.16.6.1", "1-ff00:0:5", "172.16.4.1",
						tpkt.GenPath(0, 2, tpkt.Segments{
							seg_06B_1D1D_5A0.Macs(hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
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
							revsegSP_5A0_1D1DX_1D1DX_06BV.Macs(hMac, 1, 2),
							seg_08AV_3A0X_3C0X},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_131", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.13.2", 50000, "192.168.13.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							revsegSP_5A0_1D1DX_1D1DX_06BV.Macs(hMac, 1, 2),
							seg_08AV_3A0X_3C0X},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
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
							revsegSP_3C0X_3A0X_08AV,
							segSP_06BV_1D1DX_1D1DX_5A0.Macs(hMac, 1, 2)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_151", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:3", "173.16.3.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 3, tpkt.Segments{
							revsegSP_3C0X_3A0X_08AV,
							segSP_06BV_1D1DX_1D1DX_5A0.Macs(hMac, 1, 2)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
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
							revsegS_4B0_1D1DX_06BV.Macs(hMac, 1),
							segS_06BV_1D1DX_5A0.Macs(hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_151", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 2, tpkt.Segments{
							revsegS_4B0_1D1DX_06BV.Macs(hMac, 1),
							segS_06BV_1D1DX_5A0.Macs(hMac, 1)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
			Ignore: IgnoredPacketsBrD,
		},
	}
}
