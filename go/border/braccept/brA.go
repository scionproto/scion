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

var IgnoredPacketsBrA = []*tpkt.ExpPkt{
	{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
		tpkt.GenOverlayIP4UDP("192.168.0.11", 30041, "192.168.0.61", 30041),
		tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.101", "1-ff00:0:1", "BS_M", nil, common.L4UDP),
		tpkt.NewUDP(20001, 0, ifStateReq),
		ifStateReq,
	}}}

func genTestsBrA(hMac hash.Hash) []*BRTest {
	return []*BRTest{
		{
			Desc: "Single IFID - external - Xover Peer - local destination",
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
		// XXX should we check both segments have Peer flag set? currently not required
		{
			Desc: "Single IFID - internal - Xover Peer - remote destination",
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
			Desc: "Single IFID - external - Xover peer/child",
			In: &tpkt.Pkt{
				Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							revsegP_2C0X_2A0X_06C,
							segSP_06B_1A1DX_1D1DX_5A0.Macs(hMac, 1, 2)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.14", 30004),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 2, tpkt.Segments{
							revsegP_2C0X_2A0X_06C,
							segSP_06B_1A1DX_1D1DX_5A0.Macs(hMac, 1, 2)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Single IFID - internal - Xover child/peer",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.13", 30003, "192.168.0.11", 30001),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(0, 2, tpkt.Segments{
							revsegSP_5A0_1D1DX_1A1DX_06BV.Macs(hMac, 1, 2),
							seg_06CV_2A0X_2C0X},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							revsegSP_5A0_1D1DX_1A1DX_06BV.Macs(hMac, 1, 2),
							seg_06CV_2A0X_2C0X},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
	}
}
