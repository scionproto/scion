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

	"github.com/scionproto/scion/go/border/braccept/tpkt"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/spath"
)

var (
	if_121 = common.IFIDType(121)
	if_122 = common.IFIDType(122)
	if_131 = common.IFIDType(131)
	if_132 = common.IFIDType(132)
	if_141 = common.IFIDType(141)
	if_142 = common.IFIDType(142)
	if_151 = common.IFIDType(151)
	if_152 = common.IFIDType(152)
	if_211 = common.IFIDType(211)
	if_212 = common.IFIDType(212)
	if_311 = common.IFIDType(311)
	if_312 = common.IFIDType(312)
	if_411 = common.IFIDType(411)
	if_412 = common.IFIDType(412)
	if_511 = common.IFIDType(511)
	if_512 = common.IFIDType(512)
)

var tsNow = uint32(time.Now().Unix())

var (
	// Core paths between ff00:0:1 <-> ff00:0:2
	path_2A_1A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_211}, {ConsIngress: if_121}}},
	}
	path_2A_1A_rev = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_121}, {ConsEgress: if_211}}},
	}
	path_1A_2A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_121}, {ConsIngress: if_211}}},
	}
	path_1A_2A_rev = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_211}, {ConsEgress: if_121}}},
	}
	// Core paths between ff00:0:1 <-> ff00:0:3
	path_3A_1C = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_311}, {ConsIngress: if_131}}},
	}
	path_3A_1C_rev = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_131}, {ConsEgress: if_311}}},
	}
	path_1C_3A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_131}, {ConsIngress: if_311}}},
	}
	path_1C_3A_rev = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_311}, {ConsEgress: if_131}}},
	}
	// Core paths between ff00:0:2 <-> ff00:0:3
	path_2A_1A_1C_3A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
			Hops: []*spath.HopField{{ConsEgress: if_211},
				{ConsIngress: if_121, ConsEgress: if_131}, {ConsIngress: if_311}}},
	}
	path_2A_1A_1C_3A_rev = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
			Hops: []*spath.HopField{{ConsIngress: if_311},
				{ConsIngress: if_121, ConsEgress: if_131}, {ConsEgress: if_211}}},
	}
	path_3A_1C_1A_2A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
			Hops: []*spath.HopField{{ConsEgress: if_311},
				{ConsIngress: if_131, ConsEgress: if_121}, {ConsIngress: if_211}}},
	}
	path_3A_1C_1A_2A_rev = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
			Hops: []*spath.HopField{{ConsIngress: if_211},
				{ConsIngress: if_131, ConsEgress: if_121}, {ConsEgress: if_311}}},
	}
	path_3A_1C_1C_2B_rev = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
			Hops: []*spath.HopField{{ConsIngress: if_212},
				{ConsIngress: if_131, ConsEgress: if_122}, {ConsEgress: if_311}}},
	}
	// Paths between ff00:0:1 <-> ff00:0:4
	path_1B_4A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_141}, {ConsIngress: if_411}}},
	}
	path_1B_4A_rev = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_411}, {ConsEgress: if_141}}},
	}
	// Paths between ff00:0:1 <-> ff00:0:5
	path_1C_5A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_151}, {ConsIngress: if_511}}},
	}
	path_1C_5A_rev = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151}}},
	}
	// Paths between ff00:0:2 <-> ff00:0:4
	path_2A_1A_X_1B_4A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_211}, {ConsIngress: if_121, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_141}, {ConsIngress: if_411}}},
	}
	path_1B_4A_rev_X_2A_1A_rev = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_411}, {ConsEgress: if_141, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_121}, {ConsEgress: if_211}}},
	}
	// Paths between ff00:0:2 <-> ff00:0:5
	path_2A_1A_X_1C_5A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_211}, {ConsIngress: if_121, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_151}, {ConsIngress: if_511}}},
	}
	path_2A_1A_X_1C_5A_rev = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_121}, {ConsEgress: if_211}}},
	}
	// Paths between ff00:0:3 <-> ff00:0:5
	path_1C_3A_rev_X_1C_5A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_311}, {ConsEgress: if_131, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_151}, {ConsIngress: if_511}}},
	}
	path_1C_5A_rev_X_1C_3A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_131}, {ConsIngress: if_311}}},
	}
	path_1C_5A_rev_X_3A_1C_rev = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_131}, {ConsEgress: if_311}}},
	}
	// Paths between ff00:0:4 <-> ff00:0:5
	path_1B_4A_rev_X_1C_5A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_411}, {ConsEgress: if_141, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_151}, {ConsIngress: if_511}}},
	}
	path_1C_5A_rev_X_1B_4A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_141}, {ConsIngress: if_411}}},
	}
	path_1C_5A_rev_X_1C_4B = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_142}, {ConsIngress: if_412}}},
	}
	path_1C_5A_rev_X_4B_1C_rev = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_142}, {ConsEgress: if_412}}},
	}
	// Bad paths - Xover CORE to CORE
	path_2A_1A_X_1C_3A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_211}, {ConsIngress: if_121, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_131, Xover: true}, {ConsIngress: if_311}}},
	}
	path_2A_1A_X_1C_3A_rev = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_311}, {ConsEgress: if_131, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_121, Xover: true}, {ConsEgress: if_211}}},
	}
	// Bad path - Xover DOWN to CORE
	path_5A_1C_X_1A_2A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_511}, {ConsIngress: if_151, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_121}, {ConsEgress: if_211}}},
	}
	// Bad path - Xover CORE to UP
	path_2A_1A_X_5A_1C = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_211}, {ConsIngress: if_121, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151}}},
	}
	// Bad paths between ff00:0:4 <-> ff00:0:4
	path_1B_4A_rev_X_1B_4A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_411}, {ConsEgress: if_141, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_141}, {ConsIngress: if_411}}},
	}
	path_1B_4A_rev_X_1C_4B = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_411}, {ConsEgress: if_141, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_142}, {ConsIngress: if_412}}},
	}
	// Bad paths between ff00:0:5 <-> ff00:0:5
	path_1C_5A_rev_X_1C_5A = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_151}, {ConsIngress: if_511}}},
	}
	path_1C_5A_rev_X_1C_5B = tpkt.Segments{
		{Inf: &spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151, Xover: true}}},
		{Inf: &spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			Hops: []*spath.HopField{{ConsEgress: if_152}, {ConsIngress: if_512}}},
	}
)

func genTestsCoreBrA(hMac hash.Hash) []*BRTest {
	return []*BRTest{
		{
			Desc: "Single IFID core - external - local destination",
			In: &tpkt.Pkt{
				Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, path_2A_1A.SetMac(0, 1, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.51", 30041),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, path_2A_1A.SetMac(0, 1, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Single IFID core - internal - remote destination",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.11", 30001),
					tpkt.NewValidScion("1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(0, 0, path_1A_2A.SetMac(0, 0, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(0, 1, path_1A_2A.SetMac(0, 0, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Single IFID core - external - Xover core/child",
			In: &tpkt.Pkt{
				Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(0, 1,
							path_2A_1A_X_1C_5A.SetMac(0, 1, hMac).SetMac(1, 0, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.13", 30003),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 0,
							path_2A_1A_X_1C_5A.SetMac(0, 1, hMac).SetMac(1, 0, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Single IFID core - internal - Xover child/core",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.13", 30003, "192.168.0.11", 30001),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(1, 0,
							path_5A_1C_X_1A_2A.SetMac(0, 1, hMac).SetMac(1, 0, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(1, 1,
							path_5A_1C_X_1A_2A.SetMac(0, 1, hMac).SetMac(1, 0, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		/* XXX Requires extension support to get the test to pass
		{
			Desc: "Single IFID - external - bad path - Xover core-core",
			In: &tpkt.Pkt{
				Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 1, path_2A_1A_X_1C_3A.SetMac(0, 0, hMac)),
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(1, 2, path_2A_1A_X_1C_3A_rev.SetMac(0, 0, hMac)),
						common.L4UDP),
					tpkt.NewUDP(scmp.C_Path, scmp.T_C_BadHopFOffset, nil),
				}}},
			},
		},
		*/
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
	}
}

func genTestsCoreBrB(hMac hash.Hash) []*BRTest {
	return []*BRTest{
		{
			Desc: "Single IFID core - external - local destination",
			In: &tpkt.Pkt{
				Dev: "ifid_141", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, path_1B_4A_rev.SetMac(0, 1, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.12", 30002, "192.168.0.51", 30041),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, path_1B_4A_rev.SetMac(0, 1, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Single IFID core - internal - remote destination",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.12", 30002),
					tpkt.NewValidScion("1-ff00:0:1", "192.168.0.51", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(0, 0, path_1B_4A.SetMac(0, 0, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_141", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.14.2", 50000, "192.168.14.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(0, 1, path_1B_4A.SetMac(0, 0, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Single IFID core - external - Xover child/child",
			In: &tpkt.Pkt{
				Dev: "ifid_141", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
					tpkt.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(0, 1,
							path_1B_4A_rev_X_1C_5A.SetMac(0, 1, hMac).SetMac(1, 0, hMac)),
						nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.12", 30002, "192.168.0.13", 30003),
					tpkt.NewGenCmnHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 0,
							path_1B_4A_rev_X_1C_5A.SetMac(0, 1, hMac).SetMac(1, 0, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Single IFID core - internal - Xover child/child",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.13", 30003, "192.168.0.12", 30002),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(1, 0, path_1C_5A_rev_X_1B_4A.SetMac(1, 0, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_141", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.14.2", 50000, "192.168.14.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(1, 1, path_1C_5A_rev_X_1B_4A.SetMac(1, 0, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Single IFID core - external - Xover child/core",
			In: &tpkt.Pkt{
				Dev: "ifid_141", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
					tpkt.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(0, 1,
							path_1B_4A_rev_X_2A_1A_rev.SetMac(0, 1, hMac).SetMac(1, 0, hMac)),
						nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.12", 30002, "192.168.0.11", 30001),
					tpkt.NewGenCmnHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(1, 0,
							path_1B_4A_rev_X_2A_1A_rev.SetMac(0, 1, hMac).SetMac(1, 0, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Single IFID core - internal - Xover core/child",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.12", 30002),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(1, 0, path_2A_1A_X_1B_4A.SetMac(1, 0, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_141", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.14.2", 50000, "192.168.14.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(1, 1, path_2A_1A_X_1B_4A.SetMac(1, 0, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		/* TODO(sgmonroy) uncomment once BR drops Xover packets entering and leaving through
		// the same ifid
		{
			Desc: "Single IFID core - external - Xover child/child - same ingress/egress ifid",
			In: &tpkt.Pkt{
				Dev: "ifid_141", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
					tpkt.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:4", "172.16.4.2",
						tpkt.GenPath(0, 1, path_1B_4A_rev_X_1B_4A.SetMac(0, 0, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{},
		},
		// TODO(sgmonroy) uncomment once BR drops packets coming from and destined to the same AS
		{
			Desc: "Single IFID core - external - Xover child/child - same ingress/egress AS",
			In: &tpkt.Pkt{
				Dev: "ifid_141", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
					tpkt.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:4", "172.16.4.2",
						tpkt.GenPath(0, 1, path_1B_4A_rev_X_1C_4B.SetMac(0, 0, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{},
		},
		*/
	}
}

func genTestsCoreBrC(hMac hash.Hash) []*BRTest {
	return []*BRTest{
		{
			Desc: "Multiple IFIDs - external - core to local",
			In: &tpkt.Pkt{
				Dev: "ifid_131", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.13.3", 40000, "192.168.13.2", 50000),
					tpkt.NewValidScion("1-ff00:0:3", "172.16.3.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, path_1C_3A_rev.SetMac(0, 1, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.13", 30003, "192.168.0.51", 30041),
					tpkt.NewGenCmnHdr("1-ff00:0:3", "172.16.3.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, path_1C_3A_rev.SetMac(0, 1, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Multiple IFIDs - internal - local to core",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.13", 30003),
					tpkt.NewValidScion("1-ff00:0:1", "192.168.0.51", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 0, path_3A_1C_rev.SetMac(0, 0, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_131", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.13.2", 50000, "192.168.13.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 1, path_3A_1C_rev.SetMac(0, 0, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Multiple IFIDs - internal - core/core",
			In: &tpkt.Pkt{
				Dev: "ifid_local", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.0.11", 30003, "192.168.0.13", 30003),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 1, path_3A_1C_1A_2A_rev.SetMac(0, 1, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_131", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.13.2", 50000, "192.168.13.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 2, path_3A_1C_1A_2A_rev.SetMac(0, 1, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Multiple IFIDs - external - core/core",
			In: &tpkt.Pkt{
				Dev: "ifid_122", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.5", 40000, "192.168.12.4", 50000),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 1, path_3A_1C_1C_2B_rev.SetMac(0, 1, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_131", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.13.2", 50000, "192.168.13.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 2, path_3A_1C_1C_2B_rev.SetMac(0, 1, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Multiple IFIDs - external - Xover core/child",
			In: &tpkt.Pkt{
				Dev: "ifid_131", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.13.3", 40000, "192.168.13.2", 50000),
					tpkt.NewValidScion("1-ff00:0:3", "172.16.3.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(0, 1,
							path_1C_3A_rev_X_1C_5A.SetMac(0, 1, hMac).SetMac(1, 0, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_151", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:3", "172.16.3.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 1,
							path_1C_3A_rev_X_1C_5A.SetMac(0, 1, hMac).SetMac(1, 0, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Multiple IFIDs - external - Xover child/core",
			In: &tpkt.Pkt{
				Dev: "ifid_151", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(0, 1,
							path_1C_5A_rev_X_3A_1C_rev.SetMac(0, 1, hMac).SetMac(1, 0, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_131", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.13.2", 50000, "192.168.13.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:3", "172.16.3.1",
						tpkt.GenPath(1, 1,
							path_1C_5A_rev_X_3A_1C_rev.SetMac(0, 1, hMac).SetMac(1, 0, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		{
			Desc: "Multiple IFIDs - external - Xover child/child",
			In: &tpkt.Pkt{
				Dev: "ifid_151", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(0, 1,
							path_1C_5A_rev_X_1C_4B.SetMac(0, 1, hMac).SetMac(1, 0, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_142", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.14.4", 50000, "192.168.14.5", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:4", "172.16.4.1",
						tpkt.GenPath(1, 1,
							path_1C_5A_rev_X_1C_4B.SetMac(0, 1, hMac).SetMac(1, 0, hMac)),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil),
				}}},
		},
		/* TODO(sgmonroy) uncomment once BR drops packets entering/leaving through the same ifid
		{
			Desc: "Multiple IFIDs core - external - Xover child/child - same ingress/egress ifid",
			In: &tpkt.Pkt{
				Dev: "ifid_151", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:5", "172.16.5.2",
						tpkt.GenPath(0, 1,
						path_1C_5A_rev_X_1C_5A.SetMac(0, 1, hMac).SetMac(1, 0, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{},
		},
		// TODO(sgmonroy) uncomment once BR drops packets coming from and destined to the same AS
		{
			Desc: "Multiple IFIDs core - external - Xover child/child - same ingress/egress AS",
			In: &tpkt.Pkt{
				Dev: "ifid_151", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
					tpkt.NewValidScion("1-ff00:0:5", "172.16.5.1", "1-ff00:0:5", "172.16.5.2",
						tpkt.GenPath(0, 1,
						path_1C_5A_rev_X_1C_5B.SetMac(0, 1, hMac).SetMac(1, 0, hMac)), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{},
		},
		*/
	}
}
