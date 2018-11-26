// +build ignore

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
)

var IgnoredPacketsCoreBrB = []*tpkt.ExpPkt{
	{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
		tpkt.GenOverlayIP4UDP("192.168.0.12", 30001, "192.168.0.61", 30041),
		tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.12", "1-ff00:0:1", "SVC_M",
			nil, common.L4UDP),
		&tpkt.PathMgmtPld{SigVerifier: ctrl.NullSigVerifier, Instance: &path_mgmt.IFStateReq{}},
	}}}

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
			Ignore: IgnoredPacketsCoreBrB,
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
			Ignore: IgnoredPacketsCoreBrB,
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
			Ignore: IgnoredPacketsCoreBrB,
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
			Ignore: IgnoredPacketsCoreBrB,
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
			Ignore: IgnoredPacketsCoreBrB,
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
			Ignore: IgnoredPacketsCoreBrB,
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
			Ignore: IgnoredPacketsCoreBrB,
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
			Ignore: IgnoredPacketsCoreBrB,
		},
		*/
	}
}
