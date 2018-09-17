// Copyright 2017 ETH Zurich
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

package spathmeta

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

func TestPathPredicates(t *testing.T) {
	conn := testGetSCIONDConn(t)

	testCases := []struct {
		name         string
		src          string
		dst          string
		predicateStr string
		expected     bool
	}{
		{
			"direct neighbors, exact match",
			"1-ff00:0:133", "1-ff00:0:132",
			"1-ff00:0:133#1019", true,
		},
		{
			"direct neighbors, not match",
			"1-ff00:0:133", "1-ff00:0:132",
			"1-ff00:0:133#1234", false,
		},
		{
			"direct neighbors, wildcard ifid match",
			"1-ff00:0:133", "1-ff00:0:132",
			"1-ff00:0:133#0", true,
		},
		{
			"direct neighbors, wildcard AS match",
			"1-ff00:0:133", "1-ff00:0:132",
			"1-0#1019", true,
		},
		{
			"direct neighbors, wildcard AS but no match",
			"1-ff00:0:133", "1-ff00:0:132",
			"1-0#1234", false,
		},
		{
			"direct neighbors, any wildcard match",
			"1-ff00:0:133", "1-ff00:0:132",
			"0-0#0", true,
		},
		{
			"direct neighbors, multiple any wildcards but no match",
			"1-ff00:0:133", "1-ff00:0:132",
			"0-0#0,0-0#0,0-0#0", false,
		},
		{
			"far neighbors, match in the middle",
			"1-ff00:0:122", "2-ff00:0:220",
			"1-ff00:0:120#3015", true,
		},
		{
			"far neighbors, match in the middle, on egress",
			"1-ff00:0:122", "2-ff00:0:220",
			"1-ff00:0:120#3022", true,
		},
		{
			"far neighbors, match at the end",
			"1-ff00:0:122", "2-ff00:0:220",
			"2-ff00:0:220#2230", true,
		},
		{
			"far neighbors, match at the start",
			"1-ff00:0:122", "2-ff00:0:220",
			"1-ff00:0:122#1815", true,
		},
		{
			"far neighbors, not match",
			"1-ff00:0:122", "2-ff00:0:220",
			"1-ff00:0:111#0", false,
		},
		{
			"far neighbors, match multiple with wildcards",
			"1-ff00:0:122", "2-ff00:0:220",
			"1-ff00:0:121#0,1-ff00:0:121#1530", true,
		},
		{
			"far neighbors, match multiple with wildcards and jumps",
			"1-ff00:0:122", "2-ff00:0:220",
			"1-ff00:0:120#3015,2-ff00:0:220#0", true,
		},
		{
			"far neighbors, not match with wildcard jumps",
			"1-ff00:0:122", "2-ff00:0:220",
			"1-ff00:0:120#0,0-0#0,1-ff00:0:110#0", false,
		},
	}

	Convey("Test for various predicates and paths", t, func() {
		for _, tc := range testCases {
			Convey(fmt.Sprintf("Test %s", tc.name), func() {
				pp, err := NewPathPredicate(tc.predicateStr)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("pp", pp, ShouldNotBeNil)

				reply, err := conn.Paths(MustParseIA(tc.dst), MustParseIA(tc.src),
					5, sciond.PathReqFlags{})
				SoMsg("paths err", err, ShouldBeNil)
				SoMsg("one path only", len(reply.Entries), ShouldEqual, 1)

				match := pp.Eval(&reply.Entries[0])
				SoMsg("match", match, ShouldEqual, tc.expected)
			})
		}
	})
}

func TestPathPredicateString(t *testing.T) {
	testCases := []struct {
		expr string
	}{
		{"1-ff00:0:133#42"},
		{"1-ff00:0:133#42,1-ff00:0:133#43"},
		{"1-ff00:0:133#0,1-ff00:0:133#0"},
		{"1-0#0"},
		{"2-0#0,2-0#0,3-0#0,3-0#0,4-ff00:0:310#1041,4-ff00:0:310#1051"},
	}
	Convey("Compile path predicates", t, func() {
		for _, tc := range testCases {
			Convey(fmt.Sprintf("Test predicate %s", tc.expr), func() {
				ppA, err := NewPathPredicate(tc.expr)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("string", ppA.String(), ShouldEqual, tc.expr)
			})
		}
	})
}

func MustParseIA(iaStr string) addr.IA {
	ia, err := addr.IAFromString(iaStr)
	if err != nil {
		panic(fmt.Sprintf("unable to parse IA %s", ia))
	}
	return ia
}

func testGetSCIONDConn(t *testing.T) sciond.Connector {
	t.Helper()

	g := graph.NewFromDescription(graph.DefaultGraphDescription)
	g.RemoveLink(graph.If_120_B1_220_X)
	service := sciond.NewMockService(g)
	conn, err := service.Connect()
	if err != nil {
		t.Fatalf("sciond init error: %s", err)
	}
	return conn
}
