package main

import (
	"hash"
	"time"

	"github.com/scionproto/scion/go/border/braccept/tpkt"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scmp"
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
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_211}, {ConsIngress: if_121}}},
	}
	path_2A_1A_rev = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_121}, {ConsEgress: if_211}}},
	}
	path_1A_2A = tpkt.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_121}, {ConsIngress: if_211}}},
	}
	path_1A_2A_rev = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_211}, {ConsEgress: if_121}}},
	}
	// Core paths between ff00:0:1 <-> ff00:0:3
	path_3A_1C = tpkt.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_311}, {ConsIngress: if_131}}},
	}
	path_3A_1C_rev = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_131}, {ConsEgress: if_311}}},
	}
	path_1C_3A = tpkt.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_131}, {ConsIngress: if_311}}},
	}
	path_1C_3A_rev = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_311}, {ConsEgress: if_131}}},
	}
	// Core paths between ff00:0:2 <-> ff00:0:3
	path_2A_1A_1C_3A = tpkt.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
			[]spath.HopField{{ConsEgress: if_211},
				{ConsIngress: if_121, ConsEgress: if_131}, {ConsIngress: if_311}}},
	}
	path_2A_1A_1C_3A_rev = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
			[]spath.HopField{{ConsIngress: if_311},
				{ConsIngress: if_121, ConsEgress: if_131}, {ConsEgress: if_211}}},
	}
	path_3A_1C_1A_2A = tpkt.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
			[]spath.HopField{{ConsEgress: if_311},
				{ConsIngress: if_131, ConsEgress: if_121}, {ConsIngress: if_211}}},
	}
	path_3A_1C_1A_2A_rev = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
			[]spath.HopField{{ConsIngress: if_211},
				{ConsIngress: if_131, ConsEgress: if_121}, {ConsEgress: if_311}}},
	}
	path_3A_1C_1C_2B_rev = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
			[]spath.HopField{{ConsIngress: if_212},
				{ConsIngress: if_131, ConsEgress: if_122}, {ConsEgress: if_311}}},
	}
	// Paths between ff00:0:1 <-> ff00:0:4
	path_1B_4A = tpkt.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_141}, {ConsIngress: if_411}}},
	}
	path_1B_4A_rev = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_411}, {ConsEgress: if_141}}},
	}
	// Paths between ff00:0:1 <-> ff00:0:5
	path_1C_5A = tpkt.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_151}, {ConsIngress: if_511}}},
	}
	path_1C_5A_rev = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151}}},
	}
	// Paths between ff00:0:2 <-> ff00:0:4
	path_2A_1A_X_1B_4A = tpkt.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_211}, {ConsIngress: if_121, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_141}, {ConsIngress: if_411}}},
	}
	path_1B_4A_rev_X_2A_1A_rev = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_411}, {ConsEgress: if_141, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_121}, {ConsEgress: if_211}}},
	}
	// Paths between ff00:0:2 <-> ff00:0:5
	path_2A_1A_X_1C_5A = tpkt.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_211}, {ConsIngress: if_121, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_151}, {ConsIngress: if_511}}},
	}
	path_2A_1A_X_1C_5A_rev = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_121}, {ConsEgress: if_211}}},
	}
	// Paths between ff00:0:3 <-> ff00:0:5
	path_1C_3A_rev_X_1C_5A = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_311}, {ConsEgress: if_131, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_151}, {ConsIngress: if_511}}},
	}
	path_1C_5A_rev_X_1C_3A = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_131}, {ConsIngress: if_311}}},
	}
	path_1C_5A_rev_X_3A_1C_rev = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_131}, {ConsEgress: if_311}}},
	}
	// Paths between ff00:0:4 <-> ff00:0:5
	path_1B_4A_rev_X_1C_5A = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_411}, {ConsEgress: if_141, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_151}, {ConsIngress: if_511}}},
	}
	path_1C_5A_rev_X_1B_4A = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_141}, {ConsIngress: if_411}}},
	}
	path_1C_5A_rev_X_1C_4A = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_142}, {ConsIngress: if_412}}},
	}
	path_1C_5A_rev_X_4A_1C_rev = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_142}, {ConsEgress: if_412}}},
	}
	// Bad paths - Xover CORE to CORE
	path_2A_1A_X_1C_3A = tpkt.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_211}, {ConsIngress: if_121, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_131, Xover: true}, {ConsIngress: if_311}}},
	}
	path_2A_1A_X_1C_3A_rev = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_311}, {ConsEgress: if_131, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_121, Xover: true}, {ConsEgress: if_211}}},
	}
	// Bad path - Xover DOWN to CORE
	path_5A_1C_X_1A_2A = tpkt.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_511}, {ConsIngress: if_151, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_121}, {ConsEgress: if_211}}},
	}
	// Bad path - Xover CORE to UP
	path_2A_1A_X_5A_1C = tpkt.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_211}, {ConsIngress: if_121, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_511}, {ConsEgress: if_151}}},
	}
	// Bad paths between ff00:0:4 <-> ff00:0:4
	path_1B_4A_rev_X_1B_4A = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_411}, {ConsEgress: if_141, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_141}, {ConsIngress: if_411}}},
	}
	path_1B_4A_rev_X_1C_4B = tpkt.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_411}, {ConsEgress: if_141, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_142}, {ConsIngress: if_412}}},
	}
)

func genTestsCoreBrA(hashMac hash.Hash) []*BRTest {
	return []*BRTest{
		{
			Desc: "Single IFID core - external - local destination",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_121",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
				AddrHdr: tpkt.NewAddrHdr(
					"1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51"),
				Path: tpkt.GenPath(1, 2, path_2A_1A, hashMac),
				L4:   tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_local",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.0.11", 30087, "192.168.0.51", 30041),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51"),
					Path: tpkt.GenPath(1, 2, path_2A_1A, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{
			Desc: "Single IFID core - internal - remote destination",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_local",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.11", 30087),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1"),
				Path:    tpkt.GenPath(1, 1, path_1A_2A, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_121",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1"),
					Path: tpkt.GenPath(1, 2, path_1A_2A, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{
			Desc: "Single IFID core - external - Xover core/child",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_121",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1"),
				Path:    tpkt.GenPath(1, 2, path_2A_1A_X_1C_5A, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_local",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.0.11", 30087, "192.168.0.13", 30087),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1"),
					Path: tpkt.GenPath(2, 1, path_2A_1A_X_1C_5A, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{
			Desc: "Single IFID core - internal - Xover child/core",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_local",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.0.13", 30087, "192.168.0.11", 30087),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1"),
				Path:    tpkt.GenPath(2, 1, path_5A_1C_X_1A_2A, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_121",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1"),
					Path: tpkt.GenPath(2, 2, path_5A_1C_X_1A_2A, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{ // XXX This test currently fail because we received an SCMP back
			Desc: "Single IFID - external - bad path - Xover core-core",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_121",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1"),
				Path:    tpkt.GenPath(1, 2, path_2A_1A_X_1C_3A, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_121",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.12.2", 50000, "192.168.12.3", 40000),
					AddrHdr: tpkt.NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1"),
					Path:    tpkt.GenPath(2, 2, path_2A_1A_X_1C_3A_rev, hashMac),
					L4:      tpkt.GenL4SCMP(scmp.C_Path, scmp.T_C_BadHopFOffset),
				}},
			},
		},
		{
			Desc: "Single IFID - external - empty overlay packet",
			In: &tpkt.Raw{Pkt: tpkt.Pkt{
				Dev:     "ifid_121",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
			}},
			Out: []tpkt.Matcher{},
		},
		{
			Desc: "Single IFID - external - Bad packet 7 Bytes",
			In: &tpkt.Raw{Pkt: tpkt.Pkt{
				Dev:     "ifid_121",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.12.3", 40000, "192.168.12.2", 50000),
				Pld:     common.RawBytes{1, 2, 3, 4, 5, 6, 7},
			}},
			Out: []tpkt.Matcher{},
		},
	}
}

func genTestsCoreBrB(hashMac hash.Hash) []*BRTest {
	return []*BRTest{
		{
			Desc: "Single IFID core - external - local destination",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_141",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
				AddrHdr: tpkt.NewAddrHdr(
					"1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51"),
				Path: tpkt.GenPath(1, 2, path_1B_4A_rev, hashMac),
				L4:   tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_local",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.0.12", 30087, "192.168.0.51", 30041),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51"),
					Path: tpkt.GenPath(1, 2, path_1B_4A_rev, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{
			Desc: "Single IFID core - internal - remote destination",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_local",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.12", 30087),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:4", "172.16.4.1"),
				Path:    tpkt.GenPath(1, 1, path_1B_4A, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_141",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.14.2", 50000, "192.168.14.3", 40000),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:1", "192.168.0.51", "1-ff00:0:4", "172.16.4.1"),
					Path: tpkt.GenPath(1, 2, path_1B_4A, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{
			Desc: "Single IFID core - external - Xover child/child",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_141",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:5", "172.16.5.1"),
				Path:    tpkt.GenPath(1, 2, path_1B_4A_rev_X_1C_5A, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_local",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.0.12", 30087, "192.168.0.13", 30087),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:4", "172.16.4.1", "1-ff00:0:5", "172.16.5.1"),
					Path: tpkt.GenPath(2, 1, path_1B_4A_rev_X_1C_5A, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{
			Desc: "Single IFID core - internal - Xover child/child",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_local",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.0.13", 30087, "192.168.0.12", 30087),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:4", "172.16.4.1"),
				Path:    tpkt.GenPath(2, 1, path_1C_5A_rev_X_1B_4A, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_141",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.14.2", 50000, "192.168.14.3", 40000),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:5", "172.16.5.1", "1-ff00:0:4", "172.16.4.1"),
					Path: tpkt.GenPath(2, 2, path_1C_5A_rev_X_1B_4A, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{
			Desc: "Single IFID core - external - Xover child/core",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_141",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:2", "172.16.2.1"),
				Path:    tpkt.GenPath(1, 2, path_1B_4A_rev_X_2A_1A_rev, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_local",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.0.12", 30087, "192.168.0.11", 30087),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:4", "172.16.4.1", "1-ff00:0:2", "172.16.2.1"),
					Path: tpkt.GenPath(2, 1, path_1B_4A_rev_X_2A_1A_rev, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{
			Desc: "Single IFID core - internal - Xover core/child",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_local",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.0.11", 30087, "192.168.0.12", 30087),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:4", "172.16.4.1"),
				Path:    tpkt.GenPath(2, 1, path_2A_1A_X_1B_4A, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_141",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.14.2", 50000, "192.168.14.3", 40000),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:2", "172.16.2.1", "1-ff00:0:4", "172.16.4.1"),
					Path: tpkt.GenPath(2, 2, path_2A_1A_X_1B_4A, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{
			Desc: "Single IFID core - external - Xover child/child - same ingress/egress ifid",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_141",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:4", "172.16.4.2"),
				Path:    tpkt.GenPath(1, 2, path_1B_4A_rev_X_1B_4A, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{},
		},
		{
			Desc: "Single IFID core - external - Xover child/child - same ingress/egress AS",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_141",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.14.3", 40000, "192.168.14.2", 50000),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:4", "172.16.4.2"),
				Path:    tpkt.GenPath(1, 2, path_1B_4A_rev_X_1C_4B, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{},
		},
	}
}

func genTestsCoreBrC(hashMac hash.Hash) []*BRTest {
	return []*BRTest{
		{
			Desc: "Multiple IFIDs - external - local destination",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_131",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.13.3", 40000, "192.168.13.2", 50000),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:3", "172.16.3.1", "1-ff00:0:1", "192.168.0.51"),
				Path:    tpkt.GenPath(1, 2, path_1C_3A_rev, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_local",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.0.13", 30087, "192.168.0.51", 30041),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:3", "172.16.3.1", "1-ff00:0:1", "192.168.0.51"),
					Path: tpkt.GenPath(1, 2, path_1C_3A_rev, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{
			Desc: "Multiple IFIDs - internal - remote destination",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_local",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.0.51", 30041, "192.168.0.13", 30087),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:3", "172.16.3.1"),
				Path:    tpkt.GenPath(1, 1, path_3A_1C_rev, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_131",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.13.2", 50000, "192.168.13.3", 40000),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:1", "192.168.0.51", "1-ff00:0:3", "172.16.3.1"),
					Path: tpkt.GenPath(1, 2, path_3A_1C_rev, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{
			Desc: "Multiple IFIDs - internal - core segment - remote destination",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_local",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.0.13", 30087, "192.168.0.13", 30087),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1"),
				Path:    tpkt.GenPath(1, 2, path_3A_1C_1A_2A_rev, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_131",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.13.2", 50000, "192.168.13.3", 40000),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1"),
					Path: tpkt.GenPath(1, 3, path_3A_1C_1A_2A_rev, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{
			Desc: "Multiple IFIDs - external - core segment - remote destination",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_122",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.12.5", 40000, "192.168.12.4", 50000),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1"),
				Path:    tpkt.GenPath(1, 2, path_3A_1C_1C_2B_rev, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_131",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.13.2", 50000, "192.168.13.3", 40000),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1"),
					Path: tpkt.GenPath(1, 3, path_3A_1C_1C_2B_rev, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{
			Desc: "Multiple IFIDs - external - Xover core/child",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_131",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.13.3", 40000, "192.168.13.2", 50000),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:3", "172.16.3.1", "1-ff00:0:5", "172.16.5.1"),
				Path:    tpkt.GenPath(1, 2, path_1C_3A_rev_X_1C_5A, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_151",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.15.2", 50000, "192.168.15.3", 40000),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:3", "172.16.3.1", "1-ff00:0:5", "172.16.5.1"),
					Path: tpkt.GenPath(2, 2, path_1C_3A_rev_X_1C_5A, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{
			Desc: "Multiple IFIDs - external - Xover child/core",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_151",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:3", "172.16.3.1"),
				Path:    tpkt.GenPath(1, 2, path_1C_5A_rev_X_3A_1C_rev, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_131",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.13.2", 50000, "192.168.13.3", 40000),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:5", "172.16.5.1", "1-ff00:0:3", "172.16.3.1"),
					Path: tpkt.GenPath(2, 2, path_1C_5A_rev_X_3A_1C_rev, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
		{
			Desc: "Multiple IFIDs - external - Xover child/child",
			In: &tpkt.ValidPkt{Pkt: tpkt.Pkt{
				Dev:     "ifid_151",
				Overlay: tpkt.GenOverlayIP4UDP("192.168.15.3", 40000, "192.168.15.2", 50000),
				AddrHdr: tpkt.NewAddrHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:3", "172.16.3.1"),
				Path:    tpkt.GenPath(1, 2, path_1C_5A_rev_X_1C_4A, hashMac),
				L4:      tpkt.GenL4UDP(40111, 40222),
			}},
			Out: []tpkt.Matcher{
				&tpkt.ValidPkt{Pkt: tpkt.Pkt{
					Dev:     "ifid_141",
					Overlay: tpkt.GenOverlayIP4UDP("192.168.14.2", 50000, "192.168.14.3", 40000),
					AddrHdr: tpkt.NewAddrHdr(
						"1-ff00:0:5", "172.16.5.1", "1-ff00:0:4", "172.16.4.1"),
					Path: tpkt.GenPath(2, 2, path_1C_5A_rev_X_1C_4A, hashMac),
					L4:   tpkt.GenL4UDP(40111, 40222),
				}},
			},
		},
	}
}
