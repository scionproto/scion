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

package pathpol

import (
	"context"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
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
				paths, err := conn.Paths(context.Background(), tc.Dst, tc.Src, 5,
					sciond.PathReqFlags{})
				SoMsg("sciond err", err, ShouldBeNil)

				inAPS := spathmeta.NewAppPathSet(paths)
				outAPS := tc.Policy.Act(inAPS).(spathmeta.AppPathSet)
				SoMsg("paths", len(outAPS), ShouldEqual, tc.ExpPathNum)
			})
		}
	})
}

func TestSequenceEval(t *testing.T) {
	testCases := []struct {
		Name       string
		Seq        *Sequence
		Src        addr.IA
		Dst        addr.IA
		ExpPathNum int
	}{
		{
			Name:       "Empty path",
			Seq:        newSequence(t, "0-0#0"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 0,
		},
		{
			Name:       "Length not matching",
			Seq:        newSequence(t, "0-0#0"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		{
			Name:       "Two Wildcard matching",
			Seq:        newSequence(t, "0-0#0 0-0#0"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name:       "Longer Wildcard matching",
			Seq:        newSequence(t, "0-0#0 0-0#0 0-0#0 0-0#0"),
			Src:        xtest.MustParseIA("1-ff00:0:122"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 2,
		},
		{
			Name:       "Two Explicit matching",
			Seq:        newSequence(t, "1-ff00:0:133#1019 1-ff00:0:132#1910"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:132"),
			ExpPathNum: 1,
		},
		{
			Name:       "AS double IF matching",
			Seq:        newSequence(t, "0 1-ff00:0:132#1910,1916 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		{
			Name:       "AS IF matching, first wildcard",
			Seq:        newSequence(t, "0 1-ff00:0:132#0,1916 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		{
			Name: "Longer Explicit matching",
			Seq: newSequence(t, "1-ff00:0:122#1815 1-ff00:0:121#1518,1530 "+
				"1-ff00:0:120#3015,3122 2-ff00:0:220#2231,2224 2-ff00:0:221#2422"),
			Src:        xtest.MustParseIA("1-ff00:0:122"),
			Dst:        xtest.MustParseIA("2-ff00:0:221"),
			ExpPathNum: 1,
		},
		{
			Name: "Longer Explicit matching, single wildcard",
			Seq: newSequence(t, "1-ff00:0:133#1018 1-ff00:0:122#1810,1815 "+
				"1-ff00:0:121#0,1530 1-ff00:0:120#3015,2911 1-ff00:0:110#1129"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		{
			Name: "Longer Explicit matching, reverse single wildcard",
			Seq: newSequence(t, "1-ff00:0:133#1018 1-ff00:0:122#1810,1815 "+
				"1-ff00:0:121#1530,0 1-ff00:0:120#3015,2911 1-ff00:0:110#1129"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 0,
		},
		{
			Name: "Longer Explicit matching, multiple wildcard",
			Seq: newSequence(t, "1-ff00:0:133#1018 1-ff00:0:122#0,1815 "+
				"1-ff00:0:121#0,1530 1-ff00:0:120#3015,0 1-ff00:0:110#1129"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		{
			Name: "Longer Explicit matching, mixed wildcard types",
			Seq: newSequence(t, "1-ff00:0:133#0 1 "+
				"0-0#0 1-ff00:0:120#0 1-ff00:0:110#1129"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		{
			Name: "Longer Explicit matching, mixed wildcard types, two paths",
			Seq: newSequence(t, "1-ff00:0:133#0 1-0#0 "+
				"0-0#0 1-0#0 1-ff00:0:110#0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 2,
		},
		{
			Name:       "Nil sequence does not filter",
			Seq:        nil,
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name:       "Asterisk matches multiple hops",
			Seq:        newSequence(t, "0*"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name:       "Asterisk matches zero hops",
			Seq:        newSequence(t, "0 0 0*"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name:       "Plus matches multiple hops",
			Seq:        newSequence(t, "0+"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name:       "Plus doesn't match zero hops",
			Seq:        newSequence(t, "0 0 0+"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		{
			Name:       "Question mark matches zero hops",
			Seq:        newSequence(t, "0 0 0?"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name:       "Question mark matches one hop",
			Seq:        newSequence(t, "0 0?"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name:       "Question mark doesn't match two hops",
			Seq:        newSequence(t, "0?"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		{
			Name:       "Successful match on hop count",
			Seq:        newSequence(t, "0 0 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 3,
		},
		{
			Name:       "Failed match on hop count",
			Seq:        newSequence(t, "0 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 0,
		},
		{
			Name:       "Select one of the intermediate ASes",
			Seq:        newSequence(t, "0 2-ff00:0:221 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 1,
		},
		{
			Name:       "Select two alternative intermediate ASes",
			Seq:        newSequence(t, "0 (2-ff00:0:221 | 2-ff00:0:210) 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 3,
		},
		{
			Name:       "Alternative intermediate ASes, but one doesn't exist",
			Seq:        newSequence(t, "0 (2-ff00:0:221 |64-12345) 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 1,
		},
		{
			Name:       "Or has higher priority than concatenation",
			Seq:        newSequence(t, "0 2-ff00:0:221|64-12345 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 1,
		},
		{
			Name:       "Question mark has higher priority than concatenation",
			Seq:        newSequence(t, "0 0 0 ?  "),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 3,
		},
		{
			Name:       "Parentheses change priority",
			Seq:        newSequence(t, "(0 0)?"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 0,
		},
		{
			Name:       "Single interface matches inbound interface",
			Seq:        newSequence(t, "0 1-ff00:0:132#1910 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		{
			Name:       "Single interface matches outbound interface",
			Seq:        newSequence(t, "0 1-ff00:0:132#1916 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		{
			Name:       "Single non-matching interface",
			Seq:        newSequence(t, "0 1-ff00:0:132#1917 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 0,
		},
		{
			Name:       "Left interface matches inbound",
			Seq:        newSequence(t, "0 1-ff00:0:132#1910,0 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		{
			Name:       "Left interface doesn't match outbound",
			Seq:        newSequence(t, "0 1-ff00:0:132#1916,0 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 0,
		},
		{
			Name:       "Right interface matches outbound",
			Seq:        newSequence(t, "0 1-ff00:0:132#0,1916 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		{
			Name:       "Right interface doesn't match inbound",
			Seq:        newSequence(t, "0 1-ff00:0:132#0,1910 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 0,
		},
	}

	conn := testGetSCIONDConn(t)
	Convey("TestSeq", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				paths, err := conn.Paths(context.Background(), tc.Dst, tc.Src, 5,
					sciond.PathReqFlags{})
				SoMsg("sciond err", err, ShouldBeNil)

				inAPS := spathmeta.NewAppPathSet(paths)
				outAPS := tc.Seq.Eval(inAPS)
				SoMsg("paths", len(outAPS), ShouldEqual, tc.ExpPathNum)
			})
		}
	})
}

var allowEntry = &ACLEntry{ACLAction(true), NewHopPredicate()}
var denyEntry = &ACLEntry{ACLAction(false), NewHopPredicate()}

func TestACLEval(t *testing.T) {
	testCases := []struct {
		Name       string
		ACL        *ACL
		Src        addr.IA
		Dst        addr.IA
		ExpPathNum int
	}{
		{
			Name: "allow everything",
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Allow, Rule: mustHopPredicate(t, "0-0#0")},
				denyEntry}},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name: "allow 2-0#0, deny rest",
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Allow, Rule: mustHopPredicate(t, "2-0#0")},
				denyEntry}},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name: "allow 2-ff00:0:212#0 and 2-ff00:0:211, deny rest",
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Allow, Rule: mustHopPredicate(t, "2-ff00:0:212#0")},
				{Action: Allow, Rule: mustHopPredicate(t, "2-ff00:0:211#0")},
				denyEntry}},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name: "allow 2-ff00:0:212#0, deny rest",
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Allow, Rule: mustHopPredicate(t, "2-ff00:0:212#0")},
				denyEntry}},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		{
			Name: "deny 1-ff00:0:110#0, 1-ff00:0:120#0, allow rest",
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:110#0")},
				{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
				allowEntry}},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("2-ff00:0:222"),
			ExpPathNum: 2,
		},
		{
			Name: "deny 1-ff00:0:110#0, 1-ff00:0:120#0 and 1-ff00:0:111#2823, allow rest",
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:110#0")},
				{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
				{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:111#2823")},
				allowEntry}},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("2-ff00:0:222"),
			ExpPathNum: 1,
		},
		{
			Name: "deny ISD1, allow certain ASes",
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Allow, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
				{Action: Allow, Rule: mustHopPredicate(t, "1-ff00:0:130#0")},
				{Action: Deny, Rule: mustHopPredicate(t, "1-0#0")},
				allowEntry}},
			Src:        xtest.MustParseIA("1-ff00:0:130"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 2,
		},
		{
			Name: "deny ISD1, allow certain ASes - wrong oder",
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Deny, Rule: mustHopPredicate(t, "1-0#0")},
				{Action: Allow, Rule: mustHopPredicate(t, "1-ff00:0:130#0")},
				{Action: Allow, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
				allowEntry}},
			Src:        xtest.MustParseIA("1-ff00:0:130"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 0,
		},
	}

	conn := testGetSCIONDConn(t)
	Convey("TestPolicy", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				paths, err := conn.Paths(context.Background(), tc.Dst, tc.Src, 5,
					sciond.PathReqFlags{})
				SoMsg("sciond err", err, ShouldBeNil)

				inAPS := spathmeta.NewAppPathSet(paths)
				outAPS := tc.ACL.Eval(inAPS)
				SoMsg("paths", len(outAPS), ShouldEqual, tc.ExpPathNum)
			})
		}
	})
}

func TestACLPanic(t *testing.T) {
	acl := &ACL{Entries: []*ACLEntry{{
		Action: Allow,
		Rule:   mustHopPredicate(t, "1-0#0")}}}

	conn := testGetSCIONDConn(t)
	Convey("TestACLPanic", t, func() {
		paths, err := conn.Paths(context.Background(), xtest.MustParseIA("2-ff00:0:211"),
			xtest.MustParseIA("2-ff00:0:212"), 5, sciond.PathReqFlags{})
		SoMsg("sciond err", err, ShouldBeNil)

		inAPS := spathmeta.NewAppPathSet(paths)
		So(func() { acl.Eval(inAPS) }, ShouldPanic)
	})
}

func TestACLConstructor(t *testing.T) {
	Convey("TestACLConstructor", t, func() {
		_, err := NewACL(&ACLEntry{
			Action: Allow,
			Rule:   mustHopPredicate(t, "1-0#0")})
		SoMsg("constructor", err, ShouldResemble,
			common.NewBasicError("ACL does not have a default", nil))
		acl, err := NewACL(&ACLEntry{
			Action: Allow,
			Rule:   mustHopPredicate(t, "1-0#0")},
			&ACLEntry{
				Action: Deny,
				Rule:   mustHopPredicate(t, "0-0#0")})
		SoMsg("err", err, ShouldBeNil)
		SoMsg("acl", acl, ShouldNotBeNil)
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
			Policy: NewPolicy("", nil, nil, []Option{
				{
					Policy: &Policy{
						ACL: &ACL{Entries: []*ACLEntry{
							{
								Action: Allow,
								Rule:   mustHopPredicate(t, "0-0#0")},
							denyEntry}}},
					Weight: 0},
			}),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name: "two options, deny everything",
			Policy: NewPolicy("", nil, nil, []Option{
				{
					Policy: &Policy{
						ACL: &ACL{Entries: []*ACLEntry{{
							Action: Allow,
							Rule:   mustHopPredicate(t, "0-0#0")},
							denyEntry}}},
					Weight: 0},
				{
					Policy: &Policy{
						ACL: &ACL{Entries: []*ACLEntry{{
							Action: Deny,
							Rule:   mustHopPredicate(t, "0-0#0")},
							denyEntry}}},
					Weight: 1},
			}),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		{
			Name: "two options, first: allow everything, second: allow one path",
			Policy: NewPolicy("", nil, nil, []Option{
				{Policy: &Policy{ACL: &ACL{Entries: []*ACLEntry{
					{Action: Allow, Rule: mustHopPredicate(t, "0-0#0")},
					denyEntry}}},
					Weight: 0},
				{Policy: &Policy{ACL: &ACL{Entries: []*ACLEntry{
					{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:110#0")},
					{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
					{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:111#2823")},
					allowEntry}}},
					Weight: 1},
			}),
			Src:        xtest.MustParseIA("1-ff00:0:122"),
			Dst:        xtest.MustParseIA("2-ff00:0:222"),
			ExpPathNum: 1,
		},
		{
			Name: "two options, combined",
			Policy: NewPolicy("", nil, nil, []Option{
				{Policy: &Policy{ACL: &ACL{Entries: []*ACLEntry{
					{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
					allowEntry}}},
					Weight: 0},
				{Policy: &Policy{ACL: &ACL{Entries: []*ACLEntry{
					{Action: Deny, Rule: mustHopPredicate(t, "2-ff00:0:210#0")},
					allowEntry}}},
					Weight: 0},
			}),
			Src:        xtest.MustParseIA("1-ff00:0:110"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 3,
		},
		{
			Name: "two options, take first",
			Policy: NewPolicy("", nil, nil, []Option{
				{Policy: &Policy{ACL: &ACL{Entries: []*ACLEntry{
					{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
					allowEntry}}},
					Weight: 1},
				{Policy: &Policy{ACL: &ACL{Entries: []*ACLEntry{
					{Action: Deny, Rule: mustHopPredicate(t, "2-ff00:0:210#0")},
					allowEntry}}},
					Weight: 0},
			}),
			Src:        xtest.MustParseIA("1-ff00:0:110"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 1,
		},
		{
			Name: "two options, take second",
			Policy: NewPolicy("", nil, nil, []Option{
				{Policy: &Policy{ACL: &ACL{Entries: []*ACLEntry{
					{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
					allowEntry}}},
					Weight: 1},
				{Policy: &Policy{ACL: &ACL{Entries: []*ACLEntry{
					{Action: Deny, Rule: mustHopPredicate(t, "2-ff00:0:210#0")},
					allowEntry}}},
					Weight: 10},
			}),
			Src:        xtest.MustParseIA("1-ff00:0:110"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 2,
		},
	}

	conn := testGetSCIONDConn(t)
	Convey("TestPolicy", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				paths, err := conn.Paths(context.Background(), tc.Dst, tc.Src, 5,
					sciond.PathReqFlags{})
				SoMsg("sciond err", err, ShouldBeNil)

				inAPS := spathmeta.NewAppPathSet(paths)
				outAPS := tc.Policy.Act(inAPS).(spathmeta.AppPathSet)
				SoMsg("paths", len(outAPS), ShouldEqual, tc.ExpPathNum)
			})
		}
	})
}

func TestExtends(t *testing.T) {
	testCases := []struct {
		Name           string
		Policy         *ExtPolicy
		Extended       []*ExtPolicy
		ExtendedPolicy *Policy
	}{
		{
			Name: "one extends, use sub acl",
			Policy: &ExtPolicy{
				Extends: []string{"policy1"}},
			Extended: []*ExtPolicy{
				{
					Policy: &Policy{Name: "policy1",
						ACL: &ACL{Entries: []*ACLEntry{{
							Action: Allow,
							Rule:   mustHopPredicate(t, "0-0#0")},
							denyEntry}}}},
			},
			ExtendedPolicy: &Policy{
				ACL: &ACL{Entries: []*ACLEntry{{
					Action: Allow,
					Rule:   mustHopPredicate(t, "0-0#0")},
					denyEntry}}},
		},
		{
			Name: "use option of extended policy",
			Policy: &ExtPolicy{
				Extends: []string{"policy1"}},
			Extended: []*ExtPolicy{
				{
					Policy: &Policy{Name: "policy1", Options: []Option{
						{
							Weight: 1,
							Policy: &Policy{ACL: &ACL{Entries: []*ACLEntry{{
								Action: Allow,
								Rule:   mustHopPredicate(t, "0-0#0")},
								denyEntry}}},
						},
					}}},
			},
			ExtendedPolicy: &Policy{Options: []Option{
				{
					Weight: 1,
					Policy: &Policy{ACL: &ACL{Entries: []*ACLEntry{{
						Action: Allow,
						Rule:   mustHopPredicate(t, "0-0#0")},
						denyEntry}},
					},
				},
			},
			},
		},
		{
			Name:   "two extends, use sub acl and list",
			Policy: &ExtPolicy{Extends: []string{"policy1"}},
			Extended: []*ExtPolicy{
				{
					Policy: &Policy{Name: "policy1",
						ACL: &ACL{Entries: []*ACLEntry{{
							Action: Allow,
							Rule:   mustHopPredicate(t, "0-0#0")},
							denyEntry}},
						Sequence: newSequence(t,
							"1-ff00:0:133#1019 1-ff00:0:132#1910")}},
			},
			ExtendedPolicy: &Policy{ACL: &ACL{Entries: []*ACLEntry{{
				Action: Allow,
				Rule:   mustHopPredicate(t, "0-0#0")},
				denyEntry}},
				Sequence: newSequence(t, "1-ff00:0:133#1019 1-ff00:0:132#1910")},
		},
		{
			Name: "two extends, only use acl",
			Policy: &ExtPolicy{
				Policy: &Policy{
					Sequence: newSequence(t, "1-ff00:0:133#0 1-ff00:0:132#0")},
				Extends: []string{"policy2"}},
			Extended: []*ExtPolicy{
				{Policy: &Policy{Name: "policy2", ACL: &ACL{Entries: []*ACLEntry{{
					Action: Allow,
					Rule:   mustHopPredicate(t, "0-0#0")},
					denyEntry}}}},
				{Policy: &Policy{Name: "policy1",
					Sequence: newSequence(t,
						"1-ff00:0:133#1019 1-ff00:0:132#1910")},
				}},
			ExtendedPolicy: &Policy{ACL: &ACL{Entries: []*ACLEntry{{
				Action: Allow,
				Rule:   mustHopPredicate(t, "0-0#0")},
				denyEntry}},
				Sequence: newSequence(t, "1-ff00:0:133#0 1-ff00:0:132#0")},
		},
		{
			Name: "three extends, use last list",
			Policy: &ExtPolicy{
				Extends: []string{"p1", "p2", "p3"}},
			Extended: []*ExtPolicy{
				{
					Policy: &Policy{Name: "p1",
						Sequence: newSequence(t,
							"1-ff00:0:133#1011 1-ff00:0:132#1911")}},
				{
					Policy: &Policy{Name: "p2",
						Sequence: newSequence(t,
							"1-ff00:0:133#1012 1-ff00:0:132#1912")}},
				{
					Policy: &Policy{Name: "p3",
						Sequence: newSequence(t,
							"1-ff00:0:133#1013 1-ff00:0:132#1913")}},
			},
			ExtendedPolicy: &Policy{
				Sequence: newSequence(t, "1-ff00:0:133#1013 1-ff00:0:132#1913")},
		},
		{
			Name: "nested extends",
			Policy: &ExtPolicy{
				Extends: []string{"policy1"}},
			Extended: []*ExtPolicy{
				{
					Policy:  &Policy{Name: "policy1"},
					Extends: []string{"policy2"}},
				{
					Policy:  &Policy{Name: "policy2"},
					Extends: []string{"policy3"}},
				{
					Policy: &Policy{Name: "policy3",
						Sequence: newSequence(t,
							"1-ff00:0:133#1011 1-ff00:0:132#1911"),
					}},
			},
			ExtendedPolicy: &Policy{
				Sequence: newSequence(t, "1-ff00:0:133#1011 1-ff00:0:132#1911")},
		},
		{
			Name: "nested extends, evaluating order",
			Policy: &ExtPolicy{
				Extends: []string{"policy3"}},
			Extended: []*ExtPolicy{
				{
					Policy: &Policy{Name: "policy3", Sequence: newSequence(t,
						"1-ff00:0:133#1010 1-ff00:0:132#1910")},
					Extends: []string{"policy2"}},
				{
					Policy:  &Policy{Name: "policy2"},
					Extends: []string{"policy1"}},
				{
					Policy: &Policy{
						Name: "policy1", Sequence: newSequence(t,
							"1-ff00:0:133#1011 1-ff00:0:132#1911")},
				},
			},
			ExtendedPolicy: &Policy{
				Sequence: newSequence(t, "1-ff00:0:133#1010 1-ff00:0:132#1910")},
		},
		{
			Name: "different nested extends, evaluating order",
			Policy: &ExtPolicy{
				Extends: []string{"policy6"}},
			Extended: []*ExtPolicy{
				{
					Policy: &Policy{Name: "policy3",
						Sequence: newSequence(t,
							"1-ff00:0:133#1010 1-ff00:0:132#1910")},
					Extends: []string{"policy2"}},
				{
					Policy:  &Policy{Name: "policy2"},
					Extends: []string{"policy1"}},
				{
					Policy:  &Policy{Name: "policy6"},
					Extends: []string{"policy3"}},
				{
					Policy: &Policy{Name: "policy1", Sequence: newSequence(t,
						"1-ff00:0:133#1011 1-ff00:0:132#1911")},
				},
			},
			ExtendedPolicy: &Policy{
				Sequence: newSequence(t, "1-ff00:0:133#1010 1-ff00:0:132#1910")},
		},
	}

	Convey("TestPolicy Extend", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				pol, err := PolicyFromExtPolicy(tc.Policy, tc.Extended)
				SoMsg("err", err, ShouldBeNil)
				SoMsg("policies", pol, ShouldResemble, tc.ExtendedPolicy)
			})
		}
	})

	Convey("TestPolicy Extend not found", t, func() {
		extPolicy := &ExtPolicy{Extends: []string{"policy1"}}
		extended := []*ExtPolicy{
			{
				Policy:  &Policy{Name: "policy1"},
				Extends: []string{"policy16"}},
			{
				Policy:  &Policy{Name: "policy2"},
				Extends: []string{"policy3"}},
			{
				Policy: &Policy{Name: "policy3",
					Sequence: newSequence(t,
						"1-ff00:0:133#1011 1-ff00:0:132#1911")},
			},
		}
		_, err := PolicyFromExtPolicy(extPolicy, extended)
		SoMsg("error", err, ShouldNotBeNil)
	})
}

func TestSequenceConstructor(t *testing.T) {
	Convey("TestSequenceConstructor", t, func() {
		_, err := NewSequence("0-0-0#0")
		SoMsg("err1", err, ShouldNotBeNil)

		_, err = NewSequence("0#0#0")
		SoMsg("err2", err, ShouldNotBeNil)

		_, err = NewSequence("0")
		SoMsg("err3", err, ShouldBeNil)

		_, err = NewSequence("1#0")
		SoMsg("err4", err, ShouldNotBeNil)

		_, err = NewSequence("1-0")
		SoMsg("err5", err, ShouldBeNil)
	})
}

func newSequence(t *testing.T, str string) *Sequence {
	seq, err := NewSequence(str)
	xtest.FailOnErr(t, err)
	return seq
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

func mustPolicyFromExtPolicy(t *testing.T, extPolicy *ExtPolicy, extended []*ExtPolicy) *Policy {
	pol, err := PolicyFromExtPolicy(extPolicy, extended)
	xtest.FailOnErr(t, err)
	return pol
}

func mustHopPredicate(t *testing.T, str string) *HopPredicate {
	hp, err := HopPredicateFromString(str)
	xtest.FailOnErr(t, err)
	return hp
}
