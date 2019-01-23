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
	"github.com/scionproto/scion/go/lib/infra"
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
	tests := []*BRTest{
		{
			Desc: "Single IFID core - external - local destination",
			In: &tpkt.Pkt{
				Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
					tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
					tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.211][121.0]", hMac, 1)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.51", 30041),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.211][121.0]", hMac, 1)},
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
							segment("(C__)[0.121][211.0]", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(0, 1, tpkt.Segments{
							segment("(C__)[0.121][211.0]", hMac, 0)},
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
							segment("(C__)[0.211][X_.121.0]", hMac, 1),
							segment("(C__)[0.141][411.0]", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.12", 30002),
					tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1",
						tpkt.GenPath(1, 0, tpkt.Segments{
							segment("(C__)[0.211][X_.121.0]", hMac, 1),
							segment("(C__)[0.141][411.0]", hMac, 0)},
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
							segment("(___)[411.0][X_.0.141]", hMac, 1),
							segment("(___)[121.0][0.211]", hMac, 0)},
						), nil,
						&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
				}},
			Out: []*tpkt.ExpPkt{
				{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
					tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					tpkt.NewGenCmnHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1",
						tpkt.GenPath(1, 1, tpkt.Segments{
							segment("(___)[411.0][X_.0.141]", hMac, 1),
							segment("(___)[121.0][0.211]", hMac, 0)},
						),
						common.L4UDP),
					tpkt.NewUDP(40111, 40222, nil, nil),
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
	expScionHdr := tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.11", "1-ff00:0:2", "172.16.2.1",
		tpkt.GenPath(1, 0, tpkt.Segments{
			segment("(___)[311.0][0.131]", hMac, 1),
			segment("(___)[X_.121.0][0.211]", hMac, 0)},
		),
		common.HopByHopClass)

	expScmpHdrPld := tpkt.NewSCMP(scmp.C_Path, scmp.T_P_BadSegment, noTime,
		&expScionHdr.ScionLayer, []tpkt.LayerBuilder{
			tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
				tpkt.GenPath(1, 0, tpkt.Segments{
					segment("(C__)[0.211][X_.121.0]", hMac, 1),
					segment("(C__)[0.131][311.0]", hMac, 0)},
				), nil,
				&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil)},
		&scmp.InfoPathOffsets{InfoF: 1, HopF: 0, IfID: if_121, Ingress: true},
		common.L4UDP)

	test := &BRTest{
		Desc: "Single IFID core - Xover core-core - Bad Path",
		In: &tpkt.Pkt{
			Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
				tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
				tpkt.NewValidScion("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
					tpkt.GenPath(0, 1, tpkt.Segments{
						segment("(C__)[0.211][X_.121.0]", hMac, 1),
						segment("(C__)[0.131][311.0]", hMac, 0)},
					), nil,
					&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil),
			}},
		Out: []*tpkt.ExpPkt{
			{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
				tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
				expScionHdr,
				&tpkt.ScionSCMPExtn{Extn: scmp.Extn{Error: true}},
				expScmpHdrPld,
			}}},
		Ignore: IgnoredPacketsCoreBrA,
	}
	tests = append(tests, test)

	expScionHdr = tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.11", "1-ff00:0:2", "172.16.2.1",
		tpkt.GenPath(1, 0, tpkt.Segments{
			segment("(___)[311.0][0.131]", hMac, 1),
			segment("(___)[X_.121.0][0.211]", hMac, 0)},
		),
		common.HopByHopClass)

	expScmpHdrPld = tpkt.NewSCMP(scmp.C_Path, scmp.T_P_BadSegment, noTime,
		&expScionHdr.ScionLayer, []tpkt.LayerBuilder{
			tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
				tpkt.GenPath(1, 0, tpkt.Segments{
					segment("(C__)[0.211][X_.121.0]", hMac, 1),
					segment("(C__)[0.131][311.0]", hMac, 0)},
				),
				common.L4TCP),
			tpkt.NewPld([]byte{1, 2, 3, 4, 5, 6, 7, 8})},
		&scmp.InfoPathOffsets{InfoF: 1, HopF: 0, IfID: if_121, Ingress: true},
		common.L4TCP)

	test = &BRTest{
		Desc: "Single IFID core - Xover core-core - Bad Path Unsupported L4",
		In: &tpkt.Pkt{
			Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
				tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
				tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1",
					tpkt.GenPath(0, 1, tpkt.Segments{
						segment("(C__)[0.211][X_.121.0]", hMac, 1),
						segment("(C__)[0.131][311.0]", hMac, 0)},
					),
					common.L4TCP),
				tpkt.NewPld([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
			}},
		Out: []*tpkt.ExpPkt{
			{Dev: "ifid_121", Layers: []tpkt.LayerMatcher{
				tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
				expScionHdr,
				&tpkt.ScionSCMPExtn{Extn: scmp.Extn{Error: true}},
				expScmpHdrPld,
			}}},
		Ignore: IgnoredPacketsCoreBrA,
	}
	tests = append(tests, test)
	// We use a known IP ie. CS, so we already have ARP entry for it
	revScionHdr := tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:4", "172.16.4.1",
		tpkt.GenPath(0, 1, tpkt.Segments{
			segment("(___)[211.0][X_.0.121]", hMac, 1),
			segment("(C__)[X_.0.141][411.0]", hMac, 0)},
		),
		common.HopByHopClass)

	sRevInfo := tpkt.MustSRevInfo(222, "1-ff00:0:2", "child", tsNow32, 60)
	rev := tpkt.NewRevocation(0, 1, 222, false, sRevInfo)

	revScmpHdrPld := tpkt.NewSCMP(scmp.C_Path, scmp.T_P_RevokedIF, now,
		&revScionHdr.ScionLayer, []tpkt.LayerBuilder{
			tpkt.NewValidScion("1-ff00:0:4", "172.16.4.1", "1-ff00:0:9", "172.16.9.1",
				tpkt.GenPath(1, 1, tpkt.Segments{
					segment("(___)[411.0][X_.0.141]", hMac, 1),
					segment("(C__)[X_.0.121][211.0]", hMac, 0)},
				), nil,
				&l4.UDP{SrcPort: 40111, DstPort: 40222}, nil)},
		rev,
		common.L4UDP)

	revPsScionHdr := tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.101", "1-ff00:0:1", "PS",
		nil, common.L4UDP)
	revBsScionHdr := tpkt.NewGenCmnHdr("1-ff00:0:1", "192.168.0.101", "1-ff00:0:1", "BS",
		nil, common.L4UDP)
	revPld := &tpkt.PathMgmtPld{
		Signer:      infra.NullSigner,
		SigVerifier: infra.NullSigVerifier,
		Instance:    sRevInfo,
	}

	revLocalFork := &BRTest{
		Desc: "Single IFID core - Revocation to local destination, fork to PS and BS",
		In: &tpkt.Pkt{
			Dev: "ifid_121", Layers: []tpkt.LayerBuilder{
				tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
				revScionHdr,
				tpkt.NewSCMPExtn(common.L4SCMP, scmp.Extn{Error: true, HopByHop: true}),
				revScmpHdrPld,
			}},
		Out: []*tpkt.ExpPkt{
			{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
				tpkt.GenOverlayIP4UDP("192.168.0.11", 30001, "192.168.0.12", 30002),
				tpkt.NewGenCmnHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:4", "172.16.4.1",
					tpkt.GenPath(1, 0, tpkt.Segments{
						segment("(___)[211.0][X_.0.121]", hMac, 1),
						segment("(C__)[X_.0.141][411.0]", hMac, 0)},
					),
					common.HopByHopClass),
				&tpkt.ScionSCMPExtn{Extn: scmp.Extn{Error: true, HopByHop: true}},
				revScmpHdrPld,
			}},
			{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
				tpkt.GenOverlayIP4UDP("192.168.0.11", 30041, "192.168.0.51", 30041),
				revPsScionHdr,
				tpkt.NewUDP(20001, 0, &revPsScionHdr.ScionLayer, revPld),
				revPld,
			}},
			{Dev: "ifid_local", Layers: []tpkt.LayerMatcher{
				tpkt.GenOverlayIP4UDP("192.168.0.11", 30041, "192.168.0.61", 30041),
				revBsScionHdr,
				tpkt.NewUDP(20001, 0, &revBsScionHdr.ScionLayer, revPld),
				revPld,
			}}},
		Ignore: IgnoredPacketsCoreBrA,
	}
	tests = append(tests, revLocalFork)
	return tests
}
