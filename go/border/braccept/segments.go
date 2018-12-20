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
	"github.com/scionproto/scion/go/border/braccept/tpkt"
	"github.com/scionproto/scion/go/lib/spath"
)

var (
	// Segments between ff00:0:1 <-> ff00:0:2
	seg_02A_1A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsEgress: if_211},
			{ConsIngress: if_121},
		})
	revseg_1A0_02A = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsIngress: if_121},
			{ConsEgress: if_211},
		})
	seg_02A_1A0X = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsEgress: if_211},
			{ConsIngress: if_121, Xover: true},
		})
	revseg_1A0X_02A = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsIngress: if_121, Xover: true},
			{ConsEgress: if_211},
		})
	seg_01A_2A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsEgress: if_121},
			{ConsIngress: if_211},
		})
	revseg_2A0_01A = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsIngress: if_211},
			{ConsEgress: if_121},
		})
	// Segments between ff00:0:1 <-> ff00:0:3
	seg_03A_1C0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsEgress: if_311},
			{ConsIngress: if_131},
		})
	revseg_1C0_03A = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsIngress: if_131},
			{ConsEgress: if_311},
		})
	seg_01C_3A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsEgress: if_131},
			{ConsIngress: if_311},
		})
	revseg_3A0_01C = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsIngress: if_311},
			{ConsEgress: if_131},
		})
	revseg_3A0_01CX = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsIngress: if_311},
			{ConsEgress: if_131, Xover: true},
		})
	// Segments between ff00:0:2 <-> ff00:0:3
	seg_02A_1A1C_3A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsEgress: if_211},
			{ConsIngress: if_121, ConsEgress: if_131},
			{ConsIngress: if_311},
		})
	revseg_3A0_1A1C_02A = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsIngress: if_311},
			{ConsIngress: if_121, ConsEgress: if_131},
			{ConsEgress: if_211},
		})
	seg_03A_1C1A_2A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsEgress: if_311},
			{ConsIngress: if_131, ConsEgress: if_121},
			{ConsIngress: if_211},
		})
	revseg_2A0_1C1A_03A = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsIngress: if_211},
			{ConsIngress: if_131, ConsEgress: if_121},
			{ConsEgress: if_311},
		})
	revseg_2B0_1C1C_03A = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsIngress: if_212},
			{ConsIngress: if_131, ConsEgress: if_122},
			{ConsEgress: if_311},
		})
	// Segments between ff00:0:1 <-> ff00:0:4
	seg_01B_4A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsEgress: if_141},
			{ConsIngress: if_411},
		})
	revseg_4A0_01B = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsIngress: if_411},
			{ConsEgress: if_141},
		})
	seg_01C_4B0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsEgress: if_142},
			{ConsIngress: if_412},
		})
	revseg_4B0_01C = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsIngress: if_412},
			{ConsEgress: if_142},
		})
	revseg_4A0_01BX = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsIngress: if_411},
			{ConsEgress: if_141, Xover: true},
		})
	// Segments between ff00:0:1 <-> ff00:0:5
	seg_01C_5A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsEgress: if_151},
			{ConsIngress: if_511},
		})
	revseg_5A0_01C = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsIngress: if_511},
			{ConsEgress: if_151},
		})
	seg_01CX_5A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsEgress: if_151, Xover: true},
			{ConsIngress: if_511},
		})
	revseg_5A0_01CX = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsIngress: if_511},
			{ConsEgress: if_151, Xover: true},
		})
	// Segments between ff00:0:1 <-> ff00:0:6
	seg_01B_6A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsEgress: if_161},
			{ConsIngress: if_611},
		})
	revseg_6A0_01B = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
		[]*spath.HopField{
			{ConsIngress: if_611},
			{ConsEgress: if_161},
		})
	// Segments between ff00:0:6 <-> ff00:0:4
	seg_06B_1D1B_4A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsEgress: if_612},
			{ConsIngress: if_162, ConsEgress: if_141},
			{ConsIngress: if_411},
		})
	revseg_4A0_1D1B_06B = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsIngress: if_411},
			{ConsIngress: if_162, ConsEgress: if_141},
			{ConsEgress: if_612},
		})
	seg_06A_1C1B_4A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsEgress: if_611},
			{ConsIngress: if_161, ConsEgress: if_141},
			{ConsIngress: if_411},
		})
	revseg_4A0_1C1B_06A = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsIngress: if_411},
			{ConsIngress: if_161, ConsEgress: if_141},
			{ConsEgress: if_611},
		})
	segS_06BV_1D1BX_4A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3, Shortcut: true},
		[]*spath.HopField{
			{ConsEgress: if_612, VerifyOnly: true},
			{ConsIngress: if_162, ConsEgress: if_141, Xover: true},
			{ConsIngress: if_411},
		})
	revsegS_4A0_1D1BX_06BV = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3, Shortcut: true},
		[]*spath.HopField{
			{ConsIngress: if_411},
			{ConsIngress: if_162, ConsEgress: if_141, Xover: true},
			{ConsEgress: if_612, VerifyOnly: true},
		})
	segS_06BV_1D1DX_4B0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3, Shortcut: true},
		[]*spath.HopField{
			{ConsEgress: if_612, VerifyOnly: true},
			{ConsIngress: if_162, ConsEgress: if_142, Xover: true},
			{ConsIngress: if_412},
		})
	revsegS_4B0_1D1DX_06BV = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3, Shortcut: true},
		[]*spath.HopField{
			{ConsIngress: if_412},
			{ConsIngress: if_162, ConsEgress: if_142, Xover: true},
			{ConsEgress: if_612, VerifyOnly: true},
		})
	segSP_06A_1A1BX_1C1BX_4A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 4, Peer: true, Shortcut: true},
		[]*spath.HopField{
			{ConsEgress: if_611},
			{ConsIngress: if_121, ConsEgress: if_141, Xover: true},
			{ConsIngress: if_161, ConsEgress: if_141, Xover: true},
			{ConsIngress: if_411},
		})
	revsegSP_4A0_1C1BX_1A1BX_06AV = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 4, Peer: true, Shortcut: true},
		[]*spath.HopField{
			{ConsIngress: if_411},
			{ConsIngress: if_161, ConsEgress: if_141, Xover: true},
			{ConsIngress: if_121, ConsEgress: if_141, Xover: true},
			{ConsEgress: if_611, VerifyOnly: true},
		})
	// Segments between ff00:0:6 <-> ff00:0:5
	seg_06B_1D1D_5A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsEgress: if_612},
			{ConsIngress: if_162, ConsEgress: if_151},
			{ConsIngress: if_511},
		})
	revseg_5A0_1D1D_06B = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsIngress: if_511},
			{ConsIngress: if_162, ConsEgress: if_151},
			{ConsEgress: if_612},
		})
	segS_06BV_1D1DX_5A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3, Shortcut: true},
		[]*spath.HopField{
			{ConsEgress: if_612, VerifyOnly: true},
			{ConsIngress: if_162, ConsEgress: if_151, Xover: true},
			{ConsIngress: if_511},
		})
	revsegS_5A0_1D1DX_06BV = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3, Shortcut: true},
		[]*spath.HopField{
			{ConsIngress: if_511},
			{ConsIngress: if_162, ConsEgress: if_151, Xover: true},
			{ConsEgress: if_612, VerifyOnly: true},
		})
	segSP_06B_1A1DX_1D1DX_5A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 4, Peer: true, Shortcut: true},
		[]*spath.HopField{
			{ConsEgress: if_612},
			{ConsIngress: if_121, ConsEgress: if_151, Xover: true},
			{ConsIngress: if_162, ConsEgress: if_151, Xover: true},
			{ConsIngress: if_511},
		})
	revsegSP_5A0_1D1DX_1A1DX_06BV = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 4, Peer: true, Shortcut: true},
		[]*spath.HopField{
			{ConsIngress: if_511},
			{ConsIngress: if_162, ConsEgress: if_151, Xover: true},
			{ConsIngress: if_121, ConsEgress: if_151, Xover: true},
			{ConsEgress: if_612, VerifyOnly: true},
		})
	segSP_06BV_1D1DX_1D1DX_5A0 = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 4, Peer: true, Shortcut: true},
		[]*spath.HopField{
			{ConsEgress: if_612, VerifyOnly: true},
			{ConsIngress: if_131, ConsEgress: if_151, Xover: true},
			{ConsIngress: if_162, ConsEgress: if_151, Xover: true},
			{ConsIngress: if_511},
		})
	revsegSP_5A0_1D1DX_1D1DX_06BV = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 4, Peer: true, Shortcut: true},
		[]*spath.HopField{
			{ConsIngress: if_511},
			{ConsIngress: if_162, ConsEgress: if_151, Xover: true},
			{ConsIngress: if_131, ConsEgress: if_151, Xover: true},
			{ConsEgress: if_612, VerifyOnly: true},
		})
	// Segments between ff00:0:6 <-> ff00:0:2 with peer to ff00:0:1
	seg_06C_2A0X_2C0X = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsEgress: if_621},
			{ConsIngress: if_211, Xover: true},
			{ConsIngress: if_261, Xover: true},
		})
	seg_06CV_2A0X_2C0X = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsEgress: if_621, VerifyOnly: true},
			{ConsIngress: if_211, Xover: true},
			{ConsIngress: if_261, Xover: true},
		})
	revseg_2C0X_2A0X_06C = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsIngress: if_261, Xover: true},
			{ConsIngress: if_211, Xover: true},
			{ConsEgress: if_621},
		})
	revsegP_2C0X_2A0X_06C = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3, Peer: true},
		[]*spath.HopField{
			{ConsIngress: if_261, Xover: true},
			{ConsIngress: if_211, Xover: true},
			{ConsEgress: if_621},
		})
	// Segments between ff00:0:6 <-> ff00:0:1 with peer to ff00:0:2
	seg_06A_1A0X_1C0X = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsEgress: if_611},
			{ConsIngress: if_121, Xover: true},
			{ConsIngress: if_161, Xover: true},
		})
	revseg_1C0X_1A0X_06A = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsIngress: if_161, Xover: true},
			{ConsIngress: if_121, Xover: true},
			{ConsEgress: if_611},
		})
	revsegSP_1C0X_1A0X_06AV = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3, Peer: true, Shortcut: true},
		[]*spath.HopField{
			{ConsIngress: if_161, Xover: true},
			{ConsIngress: if_121, Xover: true},
			{ConsEgress: if_611, VerifyOnly: true},
		})
	// Segments between ff00:0:8 <-> ff00:0:3 with peer to ff00:0:1
	seg_08A_3A0X_3C0X = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsEgress: if_831},
			{ConsIngress: if_311, Xover: true},
			{ConsIngress: if_381, Xover: true},
		})
	seg_08AV_3A0X_3C0X = tpkt.NewSegment(
		&spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsEgress: if_831, VerifyOnly: true},
			{ConsIngress: if_311, Xover: true},
			{ConsIngress: if_381, Xover: true},
		})
	revseg_3C0X_3A0X_08A = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3},
		[]*spath.HopField{
			{ConsIngress: if_381, Xover: true},
			{ConsIngress: if_311, Xover: true},
			{ConsEgress: if_831},
		})
	revsegSP_3C0X_3A0X_08AV = tpkt.NewSegment(
		&spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 3, Peer: true, Shortcut: true},
		[]*spath.HopField{
			{ConsIngress: if_381, Xover: true},
			{ConsIngress: if_311, Xover: true},
			{ConsEgress: if_831, VerifyOnly: true},
		})
)
