// Copyright 2017 ETH Zurich
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

package pktcls

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

var (
	update = flag.Bool("update", false, "set to true to update reference testdata files")
)

func TestActionMap(t *testing.T) {
	testCases := []struct {
		Name     string
		FileName string
		Actions  ActionMap
	}{
		{
			Name:     "AllOf(true)",
			FileName: "act_1",
			Actions: map[string]Action{
				"A": &ActionFilterPaths{
					Name: "A",
					Cond: CondAllOf{
						CondTrue,
					},
				},
			},
		},
		{
			Name:     "AllOf(AllOf(true))",
			FileName: "act_2",
			Actions: map[string]Action{
				"A": &ActionFilterPaths{
					Name: "A",
					Cond: CondAllOf{
						CondAllOf{
							CondTrue,
						},
					},
				},
			},
		},
		{
			Name:     "AnyOf(AnyOf(false))",
			FileName: "act_3",
			Actions: map[string]Action{
				"A": &ActionFilterPaths{
					Name: "A",
					Cond: CondAnyOf{
						CondAnyOf{
							CondFalse,
						},
					},
				},
			},
		},
		{
			Name:     "CondNot(false)",
			FileName: "act_4",
			Actions: map[string]Action{
				"A": &ActionFilterPaths{
					Name: "A",
					Cond: CondNot{
						CondFalse,
					},
				},
			},
		},
		{
			Name:     "CondAnyOf(false, 0-0#123)",
			FileName: "act_5",
			Actions: map[string]Action{
				"A": &ActionFilterPaths{
					Name: "A",
					Cond: CondAnyOf{
						CondFalse,
						mustCondPathPredicate(t, "0-0#123"),
					},
				},
			},
		},
		{
			Name:     "A CondAnyOf(false) B CondAllOf(true)",
			FileName: "act_6",
			Actions: map[string]Action{
				"A": &ActionFilterPaths{
					Name: "A",
					Cond: CondAnyOf{
						CondFalse,
					},
				},
				"B": &ActionFilterPaths{
					Name: "B",
					Cond: CondAllOf{
						CondTrue,
					},
				},
			},
		},
		{
			Name:     "CondAllOf(0-0#123, 0-0#134)",
			FileName: "act_7",
			Actions: map[string]Action{
				"A": &ActionFilterPaths{
					Name: "A",
					Cond: CondAllOf{
						mustCondPathPredicate(t, "0-0#123"),
						mustCondPathPredicate(t, "0-0#134"),
					},
				},
			},
		},
		{
			Name:     "CondAnyOf(0-0#123, 0-0#134)",
			FileName: "act_8",
			Actions: map[string]Action{
				"A": &ActionFilterPaths{
					Name: "A",
					Cond: CondAnyOf{
						mustCondPathPredicate(t, "0-0#123"),
						mustCondPathPredicate(t, "0-0#134"),
					},
				},
			},
		},
		{
			Name:     "CondAnyOf(CondAllOf(0-0#123, 0-0#234), CondAllOf(0-0#345, 0-0#456))",
			FileName: "act_9",
			Actions: map[string]Action{
				"A": &ActionFilterPaths{
					Name: "A",
					Cond: CondAnyOf{
						CondAllOf{
							mustCondPathPredicate(t, "0-0#123"),
							mustCondPathPredicate(t, "0-0#234"),
						},
						CondAllOf{
							mustCondPathPredicate(t, "0-0#345"),
							mustCondPathPredicate(t, "0-0#456"),
						},
					},
				},
			},
		},
		{
			Name:     "nil ActionMap stays nil",
			FileName: "act_10",
			Actions:  nil,
		},
	}

	Convey("Test action map marshal/unmarshal", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				if *update {
					xtest.MustMarshalJSONToFile(t, tc.Actions, tc.FileName+".json")
				}

				expected, err := ioutil.ReadFile(xtest.ExpandPath(tc.FileName + ".json"))
				xtest.FailOnErr(t, err)

				// Check that marshaling matches reference files
				enc, err := json.MarshalIndent(tc.Actions, "", "    ")
				SoMsg("err marshal", err, ShouldBeNil)
				SoMsg("bytes",
					string(enc),
					ShouldResemble,
					strings.TrimRight(string(expected), "\n"))

				// Check that unmarshaling from reference files matches structure
				var actions ActionMap
				err = json.Unmarshal(expected, &actions)
				SoMsg("err unmarshal", err, ShouldBeNil)
				SoMsg("object", actions, ShouldResemble, tc.Actions)
			})
		}
	})
}

func mustCondPathPredicate(t *testing.T, str string) *CondPathPredicate {
	t.Helper()

	pp, err := spathmeta.NewPathPredicate(str)
	xtest.FailOnErr(t, err)
	return NewCondPathPredicate(pp)
}

func TestActionAct(t *testing.T) {
	type subTestCase struct {
		Name           string
		Src            addr.IA
		Dst            addr.IA
		ExpPathStrings map[string]struct{}
	}

	testCases := []struct {
		Name         string
		Action       Action
		SubTestCases []subTestCase
	}{
		{
			Name: "CondAllOf(1-ff00:0:121#1518, 1-ff00:0:120#0)",
			Action: &ActionFilterPaths{
				Name: "go through 1-ff00:0:121#1518, followed by 1-ff00:0:120#0",
				Cond: CondAllOf{
					mustCondPathPredicate(t, "1-ff00:0:121#1518"),
					mustCondPathPredicate(t, "1-ff00:0:120#0"),
				},
			},
			SubTestCases: []subTestCase{
				{
					Name:           "2-ff00:0:212 -> 2-ff00:0:210",
					Src:            xtest.MustParseIA("2-ff00:0:212"),
					Dst:            xtest.MustParseIA("2-ff00:0:210"),
					ExpPathStrings: map[string]struct{}{},
				},
				{
					Name: "1-ff00:0:122 -> 2-ff00:0:220",
					Src:  xtest.MustParseIA("1-ff00:0:122"),
					Dst:  xtest.MustParseIA("2-ff00:0:220"),
					ExpPathStrings: map[string]struct{}{
						"[1-ff00:0:122#1815 1-ff00:0:121#1518 " +
							"1-ff00:0:121#1512 1-ff00:0:120#1215 " +
							"1-ff00:0:120#1222 2-ff00:0:220#2212]": {},
					},
				},
				{
					Name: "1-ff00:0:122 -> 1-ff00:0:110",
					Src:  xtest.MustParseIA("1-ff00:0:122"),
					Dst:  xtest.MustParseIA("1-ff00:0:110"),
					ExpPathStrings: map[string]struct{}{
						"[1-ff00:0:122#1815 1-ff00:0:121#1518 " +
							"1-ff00:0:121#1512 1-ff00:0:120#1215 " +
							"1-ff00:0:120#1211 1-ff00:0:110#1112]": {},
						//"[1-ff00:0:122#1815 1-ff00:0:121#1518 " +
						//    "1-ff00:0:121#1514 "1-ff00:0:111#1415 " +
						//    "1-ff00:0:111#1411 1-ff00:0:110#1114]", Filtered
					},
				},
			},
		},
		{
			Name: "transit 1-ff00:0:132 or 1-ff00:0:121",
			Action: &ActionFilterPaths{
				Cond: CondAnyOf{
					CondAllOf{
						mustCondPathPredicate(t, "1-ff00:0:131#0"),
						mustCondPathPredicate(t, "1-ff00:0:131#0"),
					},
					CondAllOf{
						mustCondPathPredicate(t, "1-ff00:0:121#0"),
						mustCondPathPredicate(t, "1-ff00:0:121#0"),
					},
				},
			},
			SubTestCases: []subTestCase{
				{
					Name: "1-ff00:0:122 -> 2-ff00:0:220",
					Src:  xtest.MustParseIA("1-ff00:0:122"),
					Dst:  xtest.MustParseIA("2-ff00:0:220"),
					ExpPathStrings: map[string]struct{}{
						"[1-ff00:0:122#1815 1-ff00:0:121#1518 " +
							"1-ff00:0:121#1512 1-ff00:0:120#1215 " +
							"1-ff00:0:120#1222 2-ff00:0:220#2212]": {},
					},
				},
				{
					Name: "1-ff00:0:131 -> 1-ff00:0:120",
					Src:  xtest.MustParseIA("1-ff00:0:131"),
					Dst:  xtest.MustParseIA("1-ff00:0:120"),
					ExpPathStrings: map[string]struct{}{
						"[1-ff00:0:131#1613 1-ff00:0:130#1316 " +
							"1-ff00:0:130#1312 1-ff00:0:120#1213]": {},
						"[1-ff00:0:131#1615 1-ff00:0:121#1516 " +
							"1-ff00:0:121#1512 1-ff00:0:120#1215]": {},
					},
				},
				{
					Name:           "2-ff00:0:221 -> 2-ff00:0:210",
					Src:            xtest.MustParseIA("2-ff00:0:221"),
					Dst:            xtest.MustParseIA("2-ff00:0:210"),
					ExpPathStrings: map[string]struct{}{
					//"[2-ff00:0:221#2423 2-ff00:0:211#2324 " +
					//    "2-ff00:0:211#2321 2-ff00:0:210#2123]", Filtered
					//"[2-ff00:0:221#2422 2-ff00:0:220#2224 " +
					//    "2-ff00:0:220#2221 2-ff00:0:210#2122]", Filtered
					},
				},
			},
		},
	}

	conn := testGetSCIONDConn(t)
	Convey("TestActionAct", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				for _, stc := range tc.SubTestCases {
					Convey(stc.Name, func() {
						paths, err := conn.Paths(stc.Dst, stc.Src, 5, sciond.PathReqFlags{})
						SoMsg("sciond err", err, ShouldBeNil)

						inAPS := spathmeta.NewAppPathSet(paths)
						outAPS := tc.Action.Act(inAPS).(spathmeta.AppPathSet)
						SoMsg("paths", getPathStrings(outAPS), ShouldResemble, stc.ExpPathStrings)
					})
				}
			})
		}
	})
}

func testGetSCIONDConn(t *testing.T) sciond.Connector {
	t.Helper()

	g := graph.NewDefaultGraph()
	service := sciond.NewMockService(g)
	conn, err := service.Connect()
	if err != nil {
		t.Fatalf("sciond init error: %s", err)
	}
	return conn
}

func getPathStrings(aps spathmeta.AppPathSet) map[string]struct{} {
	ss := make(map[string]struct{})
	for _, v := range aps {
		ss[fmt.Sprintf("%v", v.Entry.Path.Interfaces)] = struct{}{}
	}
	return ss
}
