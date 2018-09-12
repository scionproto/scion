// Copyright 2018 ETH Zurich, Anapaya Systems
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

package graph

import "github.com/scionproto/scion/go/lib/common"

var (
	If_110_X_120_X = common.IFIDType(1112)
	If_120_X_110_X = common.IFIDType(1211)
	If_110_X_130_X = common.IFIDType(1113)
	If_130_X_110_X = common.IFIDType(1311)
	If_110_X_210_X = common.IFIDType(1121)
	If_210_X_110_X = common.IFIDType(2111)
	If_110_X_111_X = common.IFIDType(1114)
	If_111_X_110_X = common.IFIDType(1411)
	If_120_X_130_X = common.IFIDType(1213)
	If_130_X_120_X = common.IFIDType(1312)
	If_120_X_220_X = common.IFIDType(1222)
	If_220_X_120_X = common.IFIDType(2212)
	If_120_X_121_X = common.IFIDType(1215)
	If_121_X_120_X = common.IFIDType(1512)
	If_130_X_131_X = common.IFIDType(1316)
	If_131_X_130_X = common.IFIDType(1613)
	If_111_X_121_X = common.IFIDType(1415)
	If_121_X_111_X = common.IFIDType(1514)
	If_111_X_211_X = common.IFIDType(1423)
	If_211_X_111_X = common.IFIDType(2314)
	If_111_X_112_X = common.IFIDType(1417)
	If_112_X_111_X = common.IFIDType(1714)
	If_121_X_131_X = common.IFIDType(1516)
	If_131_X_121_X = common.IFIDType(1615)
	If_121_X_122_X = common.IFIDType(1518)
	If_122_X_121_X = common.IFIDType(1815)
	If_131_X_132_X = common.IFIDType(1619)
	If_132_X_131_X = common.IFIDType(1916)
	If_132_X_133_X = common.IFIDType(1910)
	If_133_X_132_X = common.IFIDType(1019)
	If_210_X_220_X = common.IFIDType(2122)
	If_220_X_210_X = common.IFIDType(2221)
	If_210_X_211_X = common.IFIDType(2123)
	If_211_X_210_X = common.IFIDType(2321)
	If_220_X_221_X = common.IFIDType(2224)
	If_221_X_220_X = common.IFIDType(2422)
	If_211_X_221_X = common.IFIDType(2324)
	If_221_X_211_X = common.IFIDType(2423)
	If_211_X_212_X = common.IFIDType(2325)
	If_212_X_211_X = common.IFIDType(2523)
	If_211_X_222_X = common.IFIDType(2326)
	If_222_X_211_X = common.IFIDType(2623)
	If_221_X_222_X = common.IFIDType(2426)
	If_222_X_221_X = common.IFIDType(2624)
)

// DefaultGraphDescription is a description of the topology in doc/fig/default-topo.pdf.
// Comments mention root name for IFIDs.
var DefaultGraphDescription = &Description{
	Nodes: []string{
		"1-ff00:0:110", // 11
		"1-ff00:0:111", // 14
		"1-ff00:0:112", // 17
		"1-ff00:0:120", // 12
		"1-ff00:0:121", // 15
		"1-ff00:0:122", // 18
		"1-ff00:0:130", // 13
		"1-ff00:0:131", // 16
		"1-ff00:0:132", // 19
		"1-ff00:0:133", // 10
		"2-ff00:0:210", // 21
		"2-ff00:0:211", // 23
		"2-ff00:0:212", // 25
		"2-ff00:0:220", // 22
		"2-ff00:0:221", // 24
		"2-ff00:0:222", // 26
	},
	Edges: []EdgeDesc{
		{"1-ff00:0:110", If_110_X_120_X, "1-ff00:0:120", If_120_X_110_X, false},
		{"1-ff00:0:110", If_110_X_130_X, "1-ff00:0:130", If_130_X_110_X, false},
		{"1-ff00:0:110", If_110_X_210_X, "2-ff00:0:210", If_210_X_110_X, false},
		{"1-ff00:0:110", If_110_X_111_X, "1-ff00:0:111", If_111_X_110_X, false},
		{"1-ff00:0:120", If_120_X_130_X, "1-ff00:0:130", If_130_X_120_X, false},
		{"1-ff00:0:120", If_120_X_220_X, "2-ff00:0:220", If_220_X_120_X, false},
		{"1-ff00:0:120", If_120_X_121_X, "1-ff00:0:121", If_121_X_120_X, false},
		{"1-ff00:0:130", If_130_X_131_X, "1-ff00:0:131", If_131_X_130_X, false},
		{"1-ff00:0:111", If_111_X_121_X, "1-ff00:0:121", If_121_X_111_X, true},
		{"1-ff00:0:111", If_111_X_211_X, "2-ff00:0:211", If_211_X_111_X, true},
		{"1-ff00:0:111", If_111_X_112_X, "1-ff00:0:112", If_112_X_111_X, false},
		{"1-ff00:0:121", If_121_X_131_X, "1-ff00:0:131", If_131_X_121_X, true},
		{"1-ff00:0:121", If_121_X_122_X, "1-ff00:0:122", If_122_X_121_X, false},
		{"1-ff00:0:131", If_131_X_132_X, "1-ff00:0:132", If_132_X_131_X, false},
		{"1-ff00:0:132", If_132_X_133_X, "1-ff00:0:133", If_133_X_132_X, false},
		{"2-ff00:0:210", If_210_X_220_X, "2-ff00:0:220", If_220_X_210_X, false},
		{"2-ff00:0:210", If_210_X_211_X, "2-ff00:0:211", If_211_X_210_X, false},
		{"2-ff00:0:220", If_220_X_221_X, "2-ff00:0:221", If_221_X_220_X, false},
		{"2-ff00:0:211", If_211_X_221_X, "2-ff00:0:221", If_221_X_211_X, true},
		{"2-ff00:0:211", If_211_X_212_X, "2-ff00:0:212", If_212_X_211_X, false},
		{"2-ff00:0:211", If_211_X_222_X, "2-ff00:0:222", If_222_X_211_X, false},
		{"2-ff00:0:221", If_221_X_222_X, "2-ff00:0:222", If_222_X_221_X, false},
	},
}
