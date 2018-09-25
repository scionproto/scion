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

package pathpcy

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

func TestBasicPolicy(t *testing.T) {
	testCases := []struct {
		Name       string
		Policy     *Policy
		Src        addr.IA
		Dst        addr.IA
		ExpPathNum int
	}{
		{
			Name:       "Empty policy",
			Policy:     &Policy{},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
	}

	conn := testGetSCIONDConn(t)
	Convey("TestPolicy", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				paths, err := conn.Paths(tc.Dst, tc.Src, 5, sciond.PathReqFlags{})
				SoMsg("sciond err", err, ShouldBeNil)

				inAPS := spathmeta.NewAppPathSet(paths)
				outAPS := tc.Policy.Act(inAPS).(spathmeta.AppPathSet)
				SoMsg("paths", len(outAPS), ShouldEqual, tc.ExpPathNum)
			})
		}
	})
}

func TestListEval(t *testing.T) {
	testCases := []struct {
		Name       string
		Policy     *Policy
		Src        addr.IA
		Dst        addr.IA
		ExpPathNum int
	}{
		{
			Name:       "Length not matching",
			Policy:     &Policy{list: []string{".."}},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		{
			Name:       "Two Wildcard matching",
			Policy:     &Policy{list: []string{"..", ".."}},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name:       "Longer Wildcard matching",
			Policy:     &Policy{list: []string{"..", "..", "..", "..", "..", "..", "..", ".."}},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 2,
		},
		{
			Name:       "Two Explicit matching",
			Policy:     &Policy{list: []string{"1-ff00:0:133#1019", "1-ff00:0:132#1910"}},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:132"),
			ExpPathNum: 1,
		},
		{
			Name: "Longer Explicit matching",
			Policy: &Policy{list: []string{"1-ff00:0:133#1018", "1-ff00:0:122#1810",
				"1-ff00:0:122#1815", "1-ff00:0:121#1518", "1-ff00:0:121#1530", "1-ff00:0:120#3015",
				"1-ff00:0:120#2911", "1-ff00:0:110#1129"}},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		{
			Name: "Longer Explicit matching, single wildcard",
			Policy: &Policy{list: []string{"1-ff00:0:133#1018", "1-ff00:0:122#1810",
				"1-ff00:0:122#1815", "..", "1-ff00:0:121#1530", "1-ff00:0:120#3015",
				"1-ff00:0:120#2911", "1-ff00:0:110#1129"}},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		{
			Name: "Longer Explicit matching, multiple wildcard",
			Policy: &Policy{list: []string{"1-ff00:0:133#1018", "..", "1-ff00:0:122#1815",
				"..", "1-ff00:0:121#1530", "1-ff00:0:120#3015", "..", "1-ff00:0:110#1129"}},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		{
			Name: "Longer Explicit matching, mixed wildcard types",
			Policy: &Policy{list: []string{"1-ff00:0:133#0", "..", "1-0#0",
				"..", "0-0#0", "1-ff00:0:120#0", "..", "1-ff00:0:110#1129"}},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		{
			Name: "Longer Explicit matching, mixed wildcard types, two paths",
			Policy: &Policy{list: []string{"1-ff00:0:133#0", "..", "1-0#0",
				"..", "0-0#0", "1-0#0", "..", "1-ff00:0:110#0"}},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 2,
		},
	}

	conn := testGetSCIONDConn(t)
	Convey("TestPolicy", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				paths, err := conn.Paths(tc.Dst, tc.Src, 5, sciond.PathReqFlags{})
				SoMsg("sciond err", err, ShouldBeNil)

				inAPS := spathmeta.NewAppPathSet(paths)
				outAPS := tc.Policy.evalPolicyList(inAPS)
				SoMsg("paths", len(outAPS), ShouldEqual, tc.ExpPathNum)
			})
		}
	})
}

func TestACLEval(t *testing.T) {
	testCases := []struct {
		Name       string
		Policy     *Policy
		Src        addr.IA
		Dst        addr.IA
		ExpPathNum int
	}{
		{
			Name: "allow everything",
			Policy: &Policy{acl: NewACL(false,
				NewACLEntry(true, mustPathInterface(t, "0-0#0")))},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name: "allow 2-0#0, deny rest",
			Policy: &Policy{acl: NewACL(false,
				NewACLEntry(true, mustPathInterface(t, "2-0#0")))},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name: "allow 2-ff00:0:212#0 and 2-ff00:0:211, deny rest",
			Policy: &Policy{acl: NewACL(false,
				NewACLEntry(true, mustPathInterface(t, "2-ff00:0:212#0")),
				NewACLEntry(true, mustPathInterface(t, "2-ff00:0:211#0")),
			)},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name: "allow 2-ff00:0:212#0, deny rest",
			Policy: &Policy{acl: NewACL(false,
				NewACLEntry(true, mustPathInterface(t, "2-ff00:0:212#0")),
			)},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		{
			Name: "deny 1-ff00:0:110#0, 1-ff00:0:120#0, allow rest",
			Policy: &Policy{acl: NewACL(true,
				NewACLEntry(false, mustPathInterface(t, "1-ff00:0:110#0")),
				NewACLEntry(false, mustPathInterface(t, "1-ff00:0:120#0")),
			)},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("2-ff00:0:222"),
			ExpPathNum: 2,
		},
		{
			Name: "deny 1-ff00:0:110#0, 1-ff00:0:120#0 and 1-ff00:0:111#2823, allow rest",
			Policy: &Policy{acl: NewACL(true,
				NewACLEntry(false, mustPathInterface(t, "1-ff00:0:110#0")),
				NewACLEntry(false, mustPathInterface(t, "1-ff00:0:120#0")),
				NewACLEntry(false, mustPathInterface(t, "1-ff00:0:111#2823")),
			)},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("2-ff00:0:222"),
			ExpPathNum: 1,
		},
		{
			Name: "deny ISD1, allow certain ASes",
			Policy: &Policy{acl: NewACL(true,
				NewACLEntry(true, mustPathInterface(t, "1-ff00:0:120#0")),
				NewACLEntry(true, mustPathInterface(t, "1-ff00:0:130#0")),
				NewACLEntry(false, mustPathInterface(t, "1-0#0")),
			)},
			Src:        xtest.MustParseIA("1-ff00:0:130"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 2,
		},
		{
			Name: "deny ISD1, allow certain ASes - wrong oder",
			Policy: &Policy{acl: NewACL(true,
				NewACLEntry(false, mustPathInterface(t, "1-0#0")),
				NewACLEntry(true, mustPathInterface(t, "1-ff00:0:130#0")),
				NewACLEntry(true, mustPathInterface(t, "1-ff00:0:120#0")),
			)},
			Src:        xtest.MustParseIA("1-ff00:0:130"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 0,
		},
	}

	conn := testGetSCIONDConn(t)
	Convey("TestPolicy", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				paths, err := conn.Paths(tc.Dst, tc.Src, 5, sciond.PathReqFlags{})
				SoMsg("sciond err", err, ShouldBeNil)

				inAPS := spathmeta.NewAppPathSet(paths)
				outAPS := tc.Policy.evalPolicyACL(inAPS)
				SoMsg("paths", len(outAPS), ShouldEqual, tc.ExpPathNum)
			})
		}
	})
}

func TestOptionsEval(t *testing.T) {
	testCases := []struct {
		Name       string
		Policy     *Policy
		Src        addr.IA
		Dst        addr.IA
		ExpPathNum int
	}{
		{
			Name: "one option, allow everything",
			Policy: &Policy{options: []PolicyOption{
				{
					policy: &Policy{
						acl: NewACL(false, NewACLEntry(true, mustPathInterface(t, "0-0#0")))},
					weight: 0},
			}},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name: "two options, deny everything",
			Policy: &Policy{options: []PolicyOption{
				{
					policy: &Policy{
						acl: NewACL(false, NewACLEntry(true, mustPathInterface(t, "0-0#0")))},
					weight: 0},
				{
					policy: &Policy{
						acl: NewACL(false, NewACLEntry(false, mustPathInterface(t, "0-0#0")))},
					weight: 1},
			}},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name: "two options, first: allow everything, second: allow one path",
			Policy: &Policy{options: []PolicyOption{
				{policy: &Policy{acl: NewACL(false,
					NewACLEntry(true, mustPathInterface(t, "0-0#0")),
				)},
					weight: 0},
				{policy: &Policy{acl: NewACL(true,
					NewACLEntry(false, mustPathInterface(t, "1-ff00:0:110#0")),
					NewACLEntry(false, mustPathInterface(t, "1-ff00:0:120#0")),
					NewACLEntry(false, mustPathInterface(t, "1-ff00:0:111#2823")),
				)},
					weight: 1},
			}},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("2-ff00:0:222"),
			ExpPathNum: 1,
		},
		{
			Name: "two options, combined",
			Policy: &Policy{options: []PolicyOption{
				{policy: &Policy{acl: NewACL(true,
					NewACLEntry(false, mustPathInterface(t, "1-ff00:0:120#0")),
				)},
					weight: 0},
				{policy: &Policy{acl: NewACL(true,
					NewACLEntry(false, mustPathInterface(t, "2-ff00:0:210#0")),
				)},
					weight: 0},
			}},
			Src:        xtest.MustParseIA("1-ff00:0:110"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 3,
		},
		{
			Name: "two options, take first",
			Policy: &Policy{options: []PolicyOption{
				{policy: &Policy{acl: NewACL(true,
					NewACLEntry(false, mustPathInterface(t, "1-ff00:0:120#0")),
				)},
					weight: 1},
				{policy: &Policy{acl: NewACL(true,
					NewACLEntry(false, mustPathInterface(t, "2-ff00:0:210#0")),
				)},
					weight: 0},
			}},
			Src:        xtest.MustParseIA("1-ff00:0:110"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 1,
		},
		{
			Name: "two options, take second",
			Policy: &Policy{options: []PolicyOption{
				{policy: &Policy{acl: NewACL(true,
					NewACLEntry(false, mustPathInterface(t, "1-ff00:0:120#0")),
				)},
					weight: 1},
				{policy: &Policy{acl: NewACL(true,
					NewACLEntry(false, mustPathInterface(t, "2-ff00:0:210#0")),
				)},
					weight: 10},
			}},
			Src:        xtest.MustParseIA("1-ff00:0:110"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 2,
		},
	}

	conn := testGetSCIONDConn(t)
	Convey("TestPolicy", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				paths, err := conn.Paths(tc.Dst, tc.Src, 5, sciond.PathReqFlags{})
				SoMsg("sciond err", err, ShouldBeNil)

				inAPS := spathmeta.NewAppPathSet(paths)
				outAPS := tc.Policy.evalOptions(inAPS)
				SoMsg("paths", len(outAPS), ShouldEqual, tc.ExpPathNum)
			})
		}
	})
}
func TestExtends(t *testing.T) {
	testCases := []struct {
		Name           string
		Policy         *Policy
		ExtendedPolicy *Policy
	}{
		{
			Name: "one extends, use sub acl",
			Policy: &Policy{extends: []*Policy{
				{acl: NewACL(false, NewACLEntry(true, mustPathInterface(t, "0-0#0")))},
			}},
			ExtendedPolicy: &Policy{
				acl: NewACL(false, NewACLEntry(true, mustPathInterface(t, "0-0#0")))},
		},
		{
			Name: "two extends, use sub acl and list",
			Policy: &Policy{extends: []*Policy{
				{acl: NewACL(false, NewACLEntry(true, mustPathInterface(t, "0-0#0")))},
				{list: []string{"1-ff00:0:133#1019", "1-ff00:0:132#1910"}},
			}},
			ExtendedPolicy: &Policy{
				acl:  NewACL(false, NewACLEntry(true, mustPathInterface(t, "0-0#0"))),
				list: []string{"1-ff00:0:133#1019", "1-ff00:0:132#1910"}},
		},
		{
			Name: "two extends, only use acl",
			Policy: &Policy{list: []string{"1-ff00:0:133#0", "1-ff00:0:132#0"},
				extends: []*Policy{
					{acl: NewACL(false, NewACLEntry(true, mustPathInterface(t, "0-0#0")))},
					{list: []string{"1-ff00:0:133#1019", "1-ff00:0:132#1910"}},
				}},
			ExtendedPolicy: &Policy{
				acl:  NewACL(false, NewACLEntry(true, mustPathInterface(t, "0-0#0"))),
				list: []string{"1-ff00:0:133#0", "1-ff00:0:132#0"}},
		},
		{
			Name: "three extends, use last list",
			Policy: &Policy{
				extends: []*Policy{
					{list: []string{"1-ff00:0:133#1011", "1-ff00:0:132#1911"}},
					{list: []string{"1-ff00:0:133#1012", "1-ff00:0:132#1912"}},
					{list: []string{"1-ff00:0:133#1013", "1-ff00:0:132#1913"}},
				}},
			ExtendedPolicy: &Policy{list: []string{"1-ff00:0:133#1013", "1-ff00:0:132#1913"}},
		},
		{
			Name: "nested extends",
			Policy: &Policy{
				extends: []*Policy{
					{
						extends: []*Policy{
							{
								extends: []*Policy{
									{
										list: []string{"1-ff00:0:133#1011", "1-ff00:0:132#1911"}},
								}},
						}},
				}},
			ExtendedPolicy: &Policy{list: []string{"1-ff00:0:133#1011", "1-ff00:0:132#1911"}},
		},
		{
			Name: "nested extends, evaluating order",
			Policy: &Policy{
				extends: []*Policy{
					{
						list: []string{"1-ff00:0:133#1010", "1-ff00:0:132#1910"},
						extends: []*Policy{
							{
								extends: []*Policy{
									{
										list: []string{"1-ff00:0:133#1011", "1-ff00:0:132#1911"}},
								}},
						}},
				}},
			ExtendedPolicy: &Policy{list: []string{"1-ff00:0:133#1010", "1-ff00:0:132#1910"}},
		},
	}

	Convey("TestPolicy Extend", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				tc.Policy.applyExtended()
				SoMsg("policies", tc.Policy, ShouldResemble, tc.ExtendedPolicy)
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

func mustPathInterface(t *testing.T, str string) *sciond.PathInterface {
	t.Helper()

	pi, err := sciond.NewPathInterface(str)
	xtest.FailOnErr(t, err)
	return &pi
}
