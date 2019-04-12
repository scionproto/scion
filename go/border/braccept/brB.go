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

	"github.com/scionproto/scion/go/border/braccept/layers"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
)

func testsBrA() int {
	var failures int

	pkt0 := AllocatePacket()
	pkt0.SetDev("ifid_local")
	pkt0.ParsePacket(`
		Ethernet: SrcMAC=00:00:00:00:00:00 DstMAC=f0:0d:ca:fe:be:ef EthernetType=IPv4
		IP4: Src=192.168.0.11 Dst=192.168.0.61 NextHdr=UDP Flags=DF Checksum=0
		UDP: Src=30041 Dst=30041
		SCION: NextHdr=UDP SrcType=IPv4 DstType=SVC
			ADDR: SrcIA=1-ff00:0:1 Src=192.168.0.101 DstIA=1-ff00:0:1 Dst=BS_M
		UDP_1: Src=20001 Dst=0
		IFStateReq:
	`)
	pkt0.SetChecksum("UDP", "IP4")
	pkt0.SetChecksum("UDP_1", "SCION")

	IgnoredPackets(pkt0)

	failures += child_local()
	failures += local_child()
	failures += child_parent()
	failures += parent_child()

	failures += xover_peer_local()
	failures += xover_local_peer()
	failures += xover_peer_child()
	failures += xover_child_peer()
	failures += revocation_owned_peer()

	ClearIgnoredPackets()

	return failures
}

var brBCtrlScionHdr = layers.NewGenCmnHdr(
	"1-ff00:0:1", "192.168.0.102", "1-ff00:0:1", "BS_M", nil, common.L4UDP)

var IgnoredPacketsBrB = []*layers.ExpPkt{
	{Dev: "ifid_local", Layers: []layers.LayerMatcher{
		layers.GenOverlayIP4UDP("192.168.0.12", 30041, "192.168.0.61", 30041),
		brBCtrlScionHdr,
		layers.NewUDP(20002, 0, &brBCtrlScionHdr.ScionLayer, ifStateReq),
		ifStateReq,
	}}}

func genTestsBrB(hMac hash.Hash) []*BRTest {
	return []*BRTest{
		{
			Desc: "Single IFID child - child/local",
			In: &layers.Pkt{
				Dev: "ifid_141", Layers: []layers.LayerBuilder{
					layers.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
					layers.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:1", "192.168.0.51",
						layers.GenPath(0, 1, layers.Segments{
							segment("(___)[411.0][0.141]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*layers.ExpPkt{
				{Dev: "ifid_local", Layers: []layers.LayerMatcher{
					layers.GenOverlayIP4UDP("192.168.0.12", 30002, "192.168.0.51", 30041),
					layers.NewGenCmnHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:1", "192.168.0.51",
						layers.GenPath(0, 1, layers.Segments{
							segment("(___)[411.0][0.141]", hMac, 1)},
						),
						common.L4UDP),
					layers.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
		{
			Desc: "Single IFID child - local/child",
			In: &layers.Pkt{
				Dev: "ifid_local", Layers: []layers.LayerBuilder{
					layers.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.12", 30002),
					layers.NewValidScion("1-ff00:0:1", "192.168.0.51", "1-ff00:0:4", "172.16.4.1",
						layers.GenPath(0, 0, layers.Segments{
							segment("(C__)[0.141][411.0]", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*layers.ExpPkt{
				{Dev: "ifid_141", Layers: []layers.LayerMatcher{
					layers.GenOverlayIP4UDP("192.168.14.2", 50000, "192.168.14.3", 40000),
					layers.NewGenCmnHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:4", "172.16.4.1",
						layers.GenPath(0, 1, layers.Segments{
							segment("(C__)[0.141][411.0]", hMac, 0)},
						),
						common.L4UDP),
					layers.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
		{
			Desc: "Single IFID child - child/parent",
			In: &layers.Pkt{
				Dev: "ifid_141", Layers: []layers.LayerBuilder{
					layers.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
					layers.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:6", "172.16.6.1",
						layers.GenPath(0, 1, layers.Segments{
							segment("(___)[411.0][162.141][0.612]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*layers.ExpPkt{
				{Dev: "ifid_local", Layers: []layers.LayerMatcher{
					layers.GenOverlayIP4UDP("192.168.0.12", 30002, "192.168.0.14", 30004),
					layers.NewGenCmnHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:6", "172.16.6.1",
						layers.GenPath(0, 1, layers.Segments{
							segment("(___)[411.0][162.141][0.612]", hMac, 1)},
						),
						common.L4UDP),
					layers.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
		{
			Desc: "Single IFID child - parent/child",
			In: &layers.Pkt{
				Dev: "ifid_local", Layers: []layers.LayerBuilder{
					layers.GenOverlayIP4UDP("192.168.0.14", 30004, "192.168.0.12", 30002),
					layers.NewValidScion("1-ff00:0:6", "172.16.6.1", "1-ff00:0:4", "172.16.4.1",
						layers.GenPath(0, 1, layers.Segments{
							segment("(C__)[0.612][162.141][411.0]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*layers.ExpPkt{
				{Dev: "ifid_141", Layers: []layers.LayerMatcher{
					layers.GenOverlayIP4UDP("192.168.14.2", 50000, "192.168.14.3", 40000),
					layers.NewGenCmnHdr("1-ff00:0:6", "172.16.6.1", "1-ff00:0:4", "172.16.4.1",
						layers.GenPath(0, 2, layers.Segments{
							segment("(C__)[0.612][162.141][411.0]", hMac, 1)},
						),
						common.L4UDP),
					layers.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
		{
			Desc: "Single IFID child - Xover child/peer",
			In: &layers.Pkt{
				Dev: "ifid_141", Layers: []layers.LayerBuilder{
					layers.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
					layers.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:2", "172.16.2.1",
						layers.GenPath(0, 1, layers.Segments{
							segment("(_SP)[411.0][X_.161.141][X_.121.141][_V.0.611]", hMac, 1, 2),
							segment("(C__)[_V.0.621][X_.211.0][X_.261.0]", nil)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*layers.ExpPkt{
				{Dev: "ifid_local", Layers: []layers.LayerMatcher{
					layers.GenOverlayIP4UDP("192.168.0.12", 30002, "192.168.0.11", 30001),
					layers.NewGenCmnHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:2", "172.16.2.1",
						layers.GenPath(0, 2, layers.Segments{
							segment("(_SP)[411.0][X_.161.141][X_.121.141][_V.0.611]", hMac, 1, 2),
							segment("(C__)[_V.0.621][X_.211.0][X_.261.0]", nil)},
						),
						common.L4UDP),
					layers.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
		{
			Desc: "Single IFID child - Xover peer/child",
			In: &layers.Pkt{
				Dev: "ifid_local", Layers: []layers.LayerBuilder{
					layers.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.12", 30002),
					layers.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:4", "172.16.4.1",
						layers.GenPath(1, 2, layers.Segments{
							segment("(__P)[X_.261.0][X_.211.0][0.621]", nil),
							segment("(CSP)[0.611][X_.121.141][X_.161.141][411.0]", hMac, 1, 2)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*layers.ExpPkt{
				{Dev: "ifid_141", Layers: []layers.LayerMatcher{
					layers.GenOverlayIP4UDP("192.168.14.2", 50000, "192.168.14.3", 40000),
					layers.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:4", "172.16.4.1",
						layers.GenPath(1, 3, layers.Segments{
							segment("(__P)[X_.261.0][X_.211.0][0.621]", nil),
							segment("(CSP)[0.611][X_.121.141][X_.161.141][411.0]", hMac, 1, 2)},
						),
						common.L4UDP),
					layers.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
		{
			Desc: "Single IFID child - Xover child/child - external",
			In: &layers.Pkt{
				Dev: "ifid_141", Layers: []layers.LayerBuilder{
					layers.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
					layers.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:5", "172.16.5.1",
						layers.GenPath(0, 1, layers.Segments{
							segment("(_S_)[411.0][X_.162.141][_V.0.612]", hMac, 1),
							segment("(CS_)[_V.0.612][X_.162.151][511.0]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*layers.ExpPkt{
				{Dev: "ifid_local", Layers: []layers.LayerMatcher{
					layers.GenOverlayIP4UDP("192.168.0.12", 30002, "192.168.0.14", 30004),
					layers.NewGenCmnHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:5", "172.16.5.1",
						layers.GenPath(1, 1, layers.Segments{
							segment("(_S_)[411.0][X_.162.141][_V.0.612]", hMac, 1),
							segment("(CS_)[_V.0.612][X_.162.151][511.0]", hMac, 1)},
						),
						common.L4UDP),
					layers.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
		{
			Desc: "Single IFID child - Xover child/child - internal",
			In: &layers.Pkt{
				Dev: "ifid_local", Layers: []layers.LayerBuilder{
					layers.GenOverlayIP4UDP("192.168.0.14", 30004, "192.168.0.12", 30002),
					layers.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:4", "172.16.4.1",
						layers.GenPath(1, 1, layers.Segments{
							segment("(_S_)[511.0][X_.162.151][_V.0.612]", hMac, 1),
							segment("(CS_)[_V.0.612][X_.162.141][411.0]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*layers.ExpPkt{
				{Dev: "ifid_141", Layers: []layers.LayerMatcher{
					layers.GenOverlayIP4UDP("192.168.14.2", 50000, "192.168.14.3", 40000),
					layers.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:4", "172.16.4.1",
						layers.GenPath(1, 2, layers.Segments{
							segment("(_S_)[511.0][X_.162.151][_V.0.612]", hMac, 1),
							segment("(CS_)[_V.0.612][X_.162.141][411.0]", hMac, 1)},
						),
						common.L4UDP),
					layers.NewUDP(40111, 40222, nil, nil),
				}}},
			Ignore: IgnoredPacketsBrB,
		},
	}
}
