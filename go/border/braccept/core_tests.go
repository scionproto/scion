package main

import (
	"time"

	"github.com/scionproto/scion/go/border/braccept/pkti"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/spath"
)

var (
	if_1201 = common.IFIDType(1201)
	if_1202 = common.IFIDType(1202)
	if_1301 = common.IFIDType(1301)
	if_1302 = common.IFIDType(1302)
	if_1401 = common.IFIDType(1401)
	if_1402 = common.IFIDType(1402)
	if_1501 = common.IFIDType(1501)
	if_1502 = common.IFIDType(1502)
	if_2101 = common.IFIDType(2101)
	if_2102 = common.IFIDType(2102)
	if_3101 = common.IFIDType(3101)
	if_3102 = common.IFIDType(3102)
	if_4101 = common.IFIDType(4101)
	if_4102 = common.IFIDType(4102)
	if_5101 = common.IFIDType(5101)
	if_5102 = common.IFIDType(5102)
)

var tsNow = uint32(time.Now().Unix())

var (
	// Core paths between ff00:0:1 <-> ff00:0:2
	path_2A_1A = pkti.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_2101}, {ConsIngress: if_1201}}},
	}
	path_2A_1A_rev = pkti.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_1201}, {ConsEgress: if_2101}}},
	}
	path_1A_2A = pkti.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_1201}, {ConsIngress: if_2101}}},
	}
	path_1A_2A_rev = pkti.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_2101}, {ConsEgress: if_1201}}},
	}
	// Core paths between ff00:0:1 <-> ff00:0:3
	path_3A_1C = pkti.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_3101}, {ConsIngress: if_1301}}},
	}
	path_3A_1C_rev = pkti.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_1301}, {ConsEgress: if_3101}}},
	}
	path_1C_3A = pkti.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_1301}, {ConsIngress: if_3101}}},
	}
	path_1C_3A_rev = pkti.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_3101}, {ConsEgress: if_1301}}},
	}
	// Core paths between ff00:0:2 <-> ff00:0:3
	path_2A_1A_1C_3A = pkti.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
			[]spath.HopField{{ConsEgress: if_2101},
				{ConsIngress: if_1201, ConsEgress: if_1301}, {ConsIngress: if_3101}}},
	}
	path_2A_1A_1C_3A_rev = pkti.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
			[]spath.HopField{{ConsIngress: if_3101},
				{ConsIngress: if_1201, ConsEgress: if_1301}, {ConsEgress: if_2101}}},
	}
	path_3A_1C_1A_2A = pkti.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
			[]spath.HopField{{ConsEgress: if_3101},
				{ConsIngress: if_1301, ConsEgress: if_1201}, {ConsIngress: if_2101}}},
	}
	path_3A_1C_1A_2A_rev = pkti.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
			[]spath.HopField{{ConsIngress: if_2101},
				{ConsIngress: if_1301, ConsEgress: if_1201}, {ConsEgress: if_3101}}},
	}
	// Paths between ff00:0:1 <-> ff00:0:4
	path_1B_4A = pkti.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_1401}, {ConsIngress: if_4101}}},
	}
	path_1B_4A_rev = pkti.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_4101}, {ConsEgress: if_1401}}},
	}
	// Paths between ff00:0:1 <-> ff00:0:5
	path_1C_5A = pkti.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_1501}, {ConsIngress: if_5101}}},
	}
	path_1C_5A_rev = pkti.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_5101}, {ConsEgress: if_1501}}},
	}
	// Paths between ff00:0:2 <-> ff00:0:4
	path_2A_1A_X_1B_4A = pkti.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_2101}, {ConsIngress: if_1201, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_1401}, {ConsIngress: if_4101}}},
	}
	path_1B_4A_rev_X_2A_1A_rev = pkti.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_4101}, {ConsEgress: if_1401, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_1201}, {ConsEgress: if_2101}}},
	}
	// Paths between ff00:0:2 <-> ff00:0:5
	// XXX Do we want all the possible paths between ff00:0:2 and ff00:0:5?
	path_2A_1A_X_1C_5A = pkti.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_2101}, {ConsIngress: if_1201, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_1501}, {ConsIngress: if_5101}}},
	}
	path_2A_1A_X_1C_5A_rev = pkti.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_5101}, {ConsEgress: if_1501, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_1201}, {ConsEgress: if_2101}}},
	}
	// Paths between ff00:0:4 <-> ff00:0:5
	// XXX Do we want all the possible paths between ff00:0:4 and ff00:0:5?
	path_1B_4A_rev_X_1C_5A = pkti.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_4101}, {ConsEgress: if_1401, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_1501}, {ConsIngress: if_5101}}},
	}
	path_1C_5A_rev_X_1B_4A = pkti.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_5101}, {ConsEgress: if_1501, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_1401}, {ConsIngress: if_4101}}},
	}
	// Bad paths - Xover CORE to CORE
	// XXX Do we want all the possible bad paths between ff00:0:2 and ff00:0:3?
	path_2A_1A_X_1C_3A = pkti.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_2101}, {ConsIngress: if_1201, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_1301, Xover: true}, {ConsIngress: if_3101}}},
	}
	path_2A_1A_X_1C_3A_rev = pkti.Segments{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_3101}, {ConsEgress: if_1301, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_1201, Xover: true}, {ConsEgress: if_2101}}},
	}
	// Bad path - Xover DOWN to CORE
	path_5A_1C_X_1A_2A = pkti.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_5101}, {ConsIngress: if_1501, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_1201}, {ConsEgress: if_2101}}},
	}
	// Bad path - Xover CORE to UP
	path_2A_1A_X_5A_1C = pkti.Segments{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_2101}, {ConsIngress: if_1201, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_5101}, {ConsEgress: if_1501}}},
	}
)

var coreBrATests []*BRTest = []*BRTest{
	{
		Desc: "Single IFID core - external - local destination",
		In: &pkti.PktGenCmn{pkti.PktInfo{
			Dev:     "ifid_1201",
			Overlay: &pkti.OverlayIP4UDP{"192.168.12.3", 40000, "192.168.12.2", 50000},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51"),
			Path:    pkti.GenPath(1, 2, path_2A_1A),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{
			&pkti.PktMerge{pkti.PktInfo{
				Dev:     "ifid_local",
				Overlay: &pkti.OverlayIP4UDP{"192.168.0.11", 30087, "192.168.0.51", 30041},
			}},
		},
	},
	{
		Desc: "Single IFID core - internal - remote destination",
		In: &pkti.PktGenCmn{pkti.PktInfo{
			Dev:     "ifid_local",
			Overlay: &pkti.OverlayIP4UDP{"192.168.0.51", 30041, "192.168.0.11", 30087},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1"),
			Path:    pkti.GenPath(1, 1, path_1A_2A),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{
			&pkti.PktMerge{pkti.PktInfo{
				Dev:     "ifid_1201",
				Overlay: &pkti.OverlayIP4UDP{"192.168.12.2", 50000, "192.168.12.3", 40000},
				Path:    pkti.GenPath(1, 2, path_1A_2A),
			}},
		},
	},
	{
		Desc: "Single IFID core - external - Xover core/child",
		In: &pkti.PktGenCmn{pkti.PktInfo{
			Dev:     "ifid_1201",
			Overlay: &pkti.OverlayIP4UDP{"192.168.12.3", 40000, "192.168.12.2", 50000},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1"),
			Path:    pkti.GenPath(1, 2, path_2A_1A_X_1C_5A),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{
			&pkti.PktMerge{pkti.PktInfo{
				Dev:     "ifid_local",
				Overlay: &pkti.OverlayIP4UDP{"192.168.0.11", 30087, "192.168.0.13", 30087},
				Path:    pkti.GenPath(2, 1, path_2A_1A_X_1C_5A),
			}},
		},
	},
	{
		Desc: "Single IFID core - internal - Xover child/core",
		In: &pkti.PktGenCmn{pkti.PktInfo{
			Dev:     "ifid_local",
			Overlay: &pkti.OverlayIP4UDP{"192.168.0.13", 30087, "192.168.0.11", 30087},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1"),
			Path:    pkti.GenPath(2, 1, path_5A_1C_X_1A_2A),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{
			&pkti.PktMerge{pkti.PktInfo{
				Dev:     "ifid_1201",
				Overlay: &pkti.OverlayIP4UDP{"192.168.12.2", 50000, "192.168.12.3", 40000},
				Path:    pkti.GenPath(2, 2, path_5A_1C_X_1A_2A),
			}},
		},
	},
	{
		Desc: "Single IFID - external - local destination - hpkt",
		In: &pkti.HpktInfo{pkti.PktInfo{
			Dev:     "ifid_1201",
			Overlay: &pkti.OverlayIP4UDP{"192.168.12.3", 40000, "192.168.12.2", 50000},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51"),
			Path:    pkti.GenPath(1, 2, path_2A_1A),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{
			&pkti.HpktInfo{pkti.PktInfo{
				Dev:     "ifid_local",
				Overlay: &pkti.OverlayIP4UDP{"192.168.0.11", 30087, "192.168.0.51", 30041},
			}},
		},
	},
	{ // XXX This test currently fail because we received an SCMP back
		Desc: "Single IFID - external - bad path - Xover core-core",
		In: &pkti.PktGenCmn{pkti.PktInfo{
			Dev:     "ifid_1201",
			Overlay: &pkti.OverlayIP4UDP{"192.168.12.3", 40000, "192.168.12.2", 50000},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1"),
			Path:    pkti.GenPath(1, 2, path_2A_1A_X_1C_3A),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{},
	},
	{
		Desc: "Single IFID - external - empty overlay packet",
		In: &pkti.PktRaw{pkti.PktInfo{
			Dev:     "ifid_1201",
			Overlay: &pkti.OverlayIP4UDP{"192.168.12.3", 40000, "192.168.12.2", 50000},
		}},
		Out: []pkti.PktMatch{},
	},
	{
		Desc: "Single IFID - external - Bad packet 7 Bytes",
		In: &pkti.PktRaw{pkti.PktInfo{
			Dev:     "ifid_1201",
			Overlay: &pkti.OverlayIP4UDP{"192.168.12.3", 40000, "192.168.12.2", 50000},
			Pld:     common.RawBytes{1, 2, 3, 4, 5, 6, 7},
		}},
		Out: []pkti.PktMatch{},
	},
}

var coreBrBTests []*BRTest = []*BRTest{
	{
		Desc: "Single IFID core - external - local destination",
		In: &pkti.PktGenCmn{pkti.PktInfo{
			Dev:     "ifid_1401",
			Overlay: &pkti.OverlayIP4UDP{"192.168.14.3", 40000, "192.168.14.2", 50000},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51"),
			Path:    pkti.GenPath(1, 2, path_1B_4A_rev),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{
			&pkti.PktMerge{pkti.PktInfo{
				Dev:     "ifid_local",
				Overlay: &pkti.OverlayIP4UDP{"192.168.0.12", 30087, "192.168.0.51", 30041},
			}},
		},
	},
	{
		Desc: "Single IFID core - internal - remote destination",
		In: &pkti.PktGenCmn{pkti.PktInfo{
			Dev:     "ifid_local",
			Overlay: &pkti.OverlayIP4UDP{"192.168.0.51", 30041, "192.168.0.12", 30087},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:4", "172.16.4.1"),
			Path:    pkti.GenPath(1, 1, path_1B_4A),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{
			&pkti.PktMerge{pkti.PktInfo{
				Dev:     "ifid_1401",
				Overlay: &pkti.OverlayIP4UDP{"192.168.14.2", 50000, "192.168.14.3", 40000},
				Path:    pkti.GenPath(1, 2, path_1B_4A),
			}},
		},
	},
	{
		Desc: "Single IFID core - external - Xover child/child",
		In: &pkti.PktGenCmn{pkti.PktInfo{
			Dev:     "ifid_1401",
			Overlay: &pkti.OverlayIP4UDP{"192.168.14.3", 40000, "192.168.14.2", 50000},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:5", "172.16.5.1"),
			Path:    pkti.GenPath(1, 2, path_1B_4A_rev_X_1C_5A),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{
			&pkti.PktMerge{pkti.PktInfo{
				Dev:     "ifid_local",
				Overlay: &pkti.OverlayIP4UDP{"192.168.0.12", 30087, "192.168.0.13", 30087},
				Path:    pkti.GenPath(2, 1, path_1B_4A_rev_X_1C_5A),
			}},
		},
	},
	{
		Desc: "Single IFID core - internal - Xover child/child",
		In: &pkti.PktGenCmn{pkti.PktInfo{
			Dev:     "ifid_local",
			Overlay: &pkti.OverlayIP4UDP{"192.168.0.13", 30087, "192.168.0.11", 30087},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:4", "172.16.4.1"),
			Path:    pkti.GenPath(2, 1, path_1C_5A_rev_X_1B_4A),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{
			&pkti.PktMerge{pkti.PktInfo{
				Dev:     "ifid_1401",
				Overlay: &pkti.OverlayIP4UDP{"192.168.14.2", 50000, "192.168.14.3", 40000},
				Path:    pkti.GenPath(2, 2, path_1C_5A_rev_X_1B_4A),
			}},
		},
	},
	{
		Desc: "Single IFID core - external - Xover child/core",
		In: &pkti.PktGenCmn{pkti.PktInfo{
			Dev:     "ifid_1401",
			Overlay: &pkti.OverlayIP4UDP{"192.168.14.3", 40000, "192.168.14.2", 50000},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:4", "172.16.4.1", "1-ff00:0:2", "172.16.2.1"),
			Path:    pkti.GenPath(1, 2, path_1B_4A_rev_X_2A_1A_rev),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{
			&pkti.PktMerge{pkti.PktInfo{
				Dev:     "ifid_local",
				Overlay: &pkti.OverlayIP4UDP{"192.168.0.12", 30087, "192.168.0.11", 30087},
				Path:    pkti.GenPath(2, 1, path_1B_4A_rev_X_2A_1A_rev),
			}},
		},
	},
	{
		Desc: "Single IFID core - internal - Xover core/child",
		In: &pkti.PktGenCmn{pkti.PktInfo{
			Dev:     "ifid_local",
			Overlay: &pkti.OverlayIP4UDP{"192.168.0.11", 30087, "192.168.0.12", 30087},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:4", "172.16.4.1"),
			Path:    pkti.GenPath(2, 1, path_2A_1A_X_1B_4A),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{
			&pkti.PktMerge{pkti.PktInfo{
				Dev:     "ifid_1401",
				Overlay: &pkti.OverlayIP4UDP{"192.168.14.2", 50000, "192.168.14.3", 40000},
				Path:    pkti.GenPath(2, 2, path_2A_1A_X_1B_4A),
			}},
		},
	},
}

var coreBrCTests []*BRTest = []*BRTest{
	{
		Desc: "Multiple IFIDs - external - local destination",
		In: &pkti.PktGenCmn{pkti.PktInfo{
			Dev:     "ifid_1301",
			Overlay: &pkti.OverlayIP4UDP{"192.168.13.3", 40000, "192.168.13.2", 50000},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:3", "172.16.3.1", "1-ff00:0:1", "192.168.0.51"),
			Path:    pkti.GenPath(1, 2, path_2A_1A),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{
			&pkti.PktMerge{pkti.PktInfo{
				Dev:     "ifid_local",
				Overlay: &pkti.OverlayIP4UDP{"192.168.0.11", 30087, "192.168.0.51", 30041},
			}},
		},
	},
	{
		Desc: "Multiple IFIDs - internal - remote destination",
		In: &pkti.PktGenCmn{pkti.PktInfo{
			Dev:     "ifid_local",
			Overlay: &pkti.OverlayIP4UDP{"192.168.0.51", 30041, "192.168.0.11", 30087},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1"),
			Path:    pkti.GenPath(1, 1, path_1A_2A),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{
			&pkti.PktMerge{pkti.PktInfo{
				Dev:     "ifid_1301",
				Overlay: &pkti.OverlayIP4UDP{"192.168.13.2", 50000, "192.168.13.3", 40000},
				Path:    pkti.GenPath(1, 2, path_1A_2A),
			}},
		},
	},
	{
		Desc: "Multiple IFIDs - external - Xover remote destination",
		In: &pkti.PktGenCmn{pkti.PktInfo{
			Dev:     "ifid_1301",
			Overlay: &pkti.OverlayIP4UDP{"192.168.13.3", 40000, "192.168.13.2", 50000},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1"),
			Path:    pkti.GenPath(1, 2, path_2A_1A_X_1C_5A),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{
			&pkti.PktMerge{pkti.PktInfo{
				Dev:     "ifid_local",
				Overlay: &pkti.OverlayIP4UDP{"192.168.0.11", 30087, "192.168.0.13", 30087},
				Path:    pkti.GenPath(2, 1, path_2A_1A_X_1C_5A),
			}},
		},
	},
	{
		Desc: "Multiple IFIDs - internal - Xover remote destination",
		In: &pkti.PktGenCmn{pkti.PktInfo{
			Dev:     "ifid_local",
			Overlay: &pkti.OverlayIP4UDP{"192.168.0.13", 30087, "192.168.0.11", 30087},
			AddrHdr: pkti.NewAddrHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1"),
			Path:    pkti.GenPath(2, 1, path_5A_1C_X_1A_2A),
			L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
		}},
		Out: []pkti.PktMatch{
			&pkti.PktMerge{pkti.PktInfo{
				Dev:     "ifid_1301",
				Overlay: &pkti.OverlayIP4UDP{"192.168.13.2", 50000, "192.168.13.3", 40000},
				Path:    pkti.GenPath(2, 2, path_5A_1C_X_1A_2A),
			}},
		},
	},
}
