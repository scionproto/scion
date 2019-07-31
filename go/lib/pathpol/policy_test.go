// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"fmt"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

func TestBasicPolicy(t *testing.T) {
	tests := map[string]struct {
		Name       string
		Policy     *Policy
		Src        addr.IA
		Dst        addr.IA
		ExpPathNum int
	}{
		"Empty policy": {
			Policy:     &Policy{},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pp := NewPathProvider(ctrl)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			paths := pp.GetPaths(test.Src, test.Dst)
			outPaths := test.Policy.Act(paths)
			assert.Equal(t, test.ExpPathNum, len(outPaths))
		})
	}
}

func TestSequenceEval(t *testing.T) {
	tests := map[string]struct {
		Seq        *Sequence
		Src        addr.IA
		Dst        addr.IA
		ExpPathNum int
	}{
		"Empty path": {
			Seq:        newSequence(t, "0-0#0"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:212"),
			ExpPathNum: 0,
		},
		"Length not matching": {
			Seq:        newSequence(t, "0-0#0"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		"Two Wildcard matching": {
			Seq:        newSequence(t, "0-0#0 0-0#0"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Longer Wildcard matching": {
			Seq:        newSequence(t, "0-0#0 0-0#0 0-0#0 0-0#0"),
			Src:        xtest.MustParseIA("1-ff00:0:122"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 2,
		},
		"Two Explicit matching": {
			Seq:        newSequence(t, "1-ff00:0:133#1019 1-ff00:0:132#1910"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:132"),
			ExpPathNum: 1,
		},
		"AS double IF matching": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1910,1916 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"AS IF matching, first wildcard": {
			Seq:        newSequence(t, "0 1-ff00:0:132#0,1916 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"Longer Explicit matching": {
			Seq: newSequence(t, "1-ff00:0:122#1815 1-ff00:0:121#1518,1530 "+
				"1-ff00:0:120#3015,3122 2-ff00:0:220#2231,2224 2-ff00:0:221#2422"),
			Src:        xtest.MustParseIA("1-ff00:0:122"),
			Dst:        xtest.MustParseIA("2-ff00:0:221"),
			ExpPathNum: 1,
		},
		"Longer Explicit matching, single wildcard": {
			Seq: newSequence(t, "1-ff00:0:133#1018 1-ff00:0:122#1810,1815 "+
				"1-ff00:0:121#0,1530 1-ff00:0:120#3015,2911 1-ff00:0:110#1129"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		"Longer Explicit matching, reverse single wildcard": {
			Seq: newSequence(t, "1-ff00:0:133#1018 1-ff00:0:122#1810,1815 "+
				"1-ff00:0:121#1530,0 1-ff00:0:120#3015,2911 1-ff00:0:110#1129"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 0,
		},
		"Longer Explicit matching, multiple wildcard": {
			Seq: newSequence(t, "1-ff00:0:133#1018 1-ff00:0:122#0,1815 "+
				"1-ff00:0:121#0,1530 1-ff00:0:120#3015,0 1-ff00:0:110#1129"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		"Longer Explicit matching, mixed wildcard types": {
			Seq: newSequence(t, "1-ff00:0:133#0 1 "+
				"0-0#0 1-ff00:0:120#0 1-ff00:0:110#1129"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 1,
		},
		"Longer Explicit matching, mixed wildcard types, two paths": {
			Seq: newSequence(t, "1-ff00:0:133#0 1-0#0 "+
				"0-0#0 1-0#0 1-ff00:0:110#0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:110"),
			ExpPathNum: 2,
		},
		"Nil sequence does not filter": {
			Seq:        nil,
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Asterisk matches multiple hops": {
			Seq:        newSequence(t, "0*"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Asterisk matches zero hops": {
			Seq:        newSequence(t, "0 0 0*"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Plus matches multiple hops": {
			Seq:        newSequence(t, "0+"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Plus doesn't match zero hops": {
			Seq:        newSequence(t, "0 0 0+"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		"Question mark matches zero hops": {
			Seq:        newSequence(t, "0 0 0?"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Question mark matches one hop": {
			Seq:        newSequence(t, "0 0?"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"Question mark doesn't match two hops": {
			Seq:        newSequence(t, "0?"),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		"Successful match on hop count": {
			Seq:        newSequence(t, "0 0 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 3,
		},
		"Failed match on hop count": {
			Seq:        newSequence(t, "0 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 0,
		},
		"Select one of the intermediate ASes": {
			Seq:        newSequence(t, "0 2-ff00:0:221 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 1,
		},
		"Select two alternative intermediate ASes": {
			Seq:        newSequence(t, "0 (2-ff00:0:221 | 2-ff00:0:210) 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 3,
		},
		"Alternative intermediate ASes, but one doesn't exist": {
			Seq:        newSequence(t, "0 (2-ff00:0:221 |64-12345) 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 1,
		},
		"Or has higher priority than concatenation": {
			Seq:        newSequence(t, "0 2-ff00:0:221|64-12345 0"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 1,
		},
		"Question mark has higher priority than concatenation": {
			Seq:        newSequence(t, "0 0 0 ?  "),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 3,
		},
		"Parentheses change priority": {
			Seq:        newSequence(t, "(0 0)?"),
			Src:        xtest.MustParseIA("2-ff00:0:211"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 0,
		},
		"Single interface matches inbound interface": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1910 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"Single interface matches outbound interface": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1916 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"Single non-matching interface": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1917 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 0,
		},
		"Left interface matches inbound": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1910,0 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"Left interface doesn't match outbound": {
			Seq:        newSequence(t, "0 1-ff00:0:132#1916,0 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 0,
		},
		"Right interface matches outbound": {
			Seq:        newSequence(t, "0 1-ff00:0:132#0,1916 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 1,
		},
		"Right interface doesn't match inbound": {
			Seq:        newSequence(t, "0 1-ff00:0:132#0,1910 0"),
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("1-ff00:0:131"),
			ExpPathNum: 0,
		},
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pp := NewPathProvider(ctrl)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			paths := pp.GetPaths(test.Src, test.Dst)
			outPaths := test.Seq.Eval(paths)
			assert.Equal(t, test.ExpPathNum, len(outPaths))
		})
	}
}

var allowEntry = &ACLEntry{ACLAction(true), NewHopPredicate()}
var denyEntry = &ACLEntry{ACLAction(false), NewHopPredicate()}

func TestACLEval(t *testing.T) {
	tests := map[string]struct {
		ACL        *ACL
		Src        addr.IA
		Dst        addr.IA
		ExpPathNum int
	}{
		"allow everything": {
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Allow, Rule: mustHopPredicate(t, "0-0#0")},
				denyEntry}},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"allow 2-0#0, deny rest": {
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Allow, Rule: mustHopPredicate(t, "2-0#0")},
				denyEntry}},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"allow 2-ff00:0:212#0 and 2-ff00:0:211, deny rest": {
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Allow, Rule: mustHopPredicate(t, "2-ff00:0:212#0")},
				{Action: Allow, Rule: mustHopPredicate(t, "2-ff00:0:211#0")},
				denyEntry}},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"allow 2-ff00:0:212#0, deny rest": {
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Allow, Rule: mustHopPredicate(t, "2-ff00:0:212#0")},
				denyEntry}},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		"deny 1-ff00:0:110#0, 1-ff00:0:120#0, allow rest": {
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:110#0")},
				{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
				allowEntry}},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("2-ff00:0:222"),
			ExpPathNum: 2,
		},
		"deny 1-ff00:0:110#0, 1-ff00:0:120#0 and 1-ff00:0:111#2823, allow rest": {
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:110#0")},
				{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
				{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:111#2823")},
				allowEntry}},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("2-ff00:0:222"),
			ExpPathNum: 1,
		},
		"deny ISD1, allow certain ASes": {
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Allow, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
				{Action: Allow, Rule: mustHopPredicate(t, "1-ff00:0:130#0")},
				{Action: Deny, Rule: mustHopPredicate(t, "1-0#0")},
				allowEntry}},
			Src:        xtest.MustParseIA("1-ff00:0:130"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 2,
		},
		"deny ISD1, allow certain ASes - wrong oder": {
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Deny, Rule: mustHopPredicate(t, "1-0#0")},
				{Action: Allow, Rule: mustHopPredicate(t, "1-ff00:0:130#0")},
				{Action: Allow, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
				allowEntry}},
			Src:        xtest.MustParseIA("1-ff00:0:130"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 0,
		},
		"nil rule should match all the paths": {
			ACL: &ACL{Entries: []*ACLEntry{
				{Action: Deny, Rule: nil},
				allowEntry}},
			Src:        xtest.MustParseIA("1-ff00:0:130"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 0,
		},
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pp := NewPathProvider(ctrl)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			paths := pp.GetPaths(test.Src, test.Dst)
			outPaths := test.ACL.Eval(paths)
			assert.Equal(t, test.ExpPathNum, len(outPaths))
		})
	}
}

func TestACLPanic(t *testing.T) {
	acl := &ACL{Entries: []*ACLEntry{{
		Action: Allow,
		Rule:   mustHopPredicate(t, "1-0#0")}}}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pp := NewPathProvider(ctrl)
	paths := pp.GetPaths(xtest.MustParseIA("2-ff00:0:212"), xtest.MustParseIA("2-ff00:0:211"))
	assert.Panics(t, func() { acl.Eval(paths) })
}

func TestACLConstructor(t *testing.T) {
	_, err := NewACL(&ACLEntry{
		Action: Allow,
		Rule:   mustHopPredicate(t, "1-0#0")})
	if assert.Error(t, err) {
		assert.Equal(t, common.NewBasicError("ACL does not have a default", nil), err)
	}
	acl, err := NewACL(&ACLEntry{
		Action: Allow,
		Rule:   mustHopPredicate(t, "1-0#0")},
		&ACLEntry{
			Action: Deny,
			Rule:   mustHopPredicate(t, "0-0#0")})
	if assert.NoError(t, err) {
		assert.NotNil(t, acl)
	}
}

func TestOptionsEval(t *testing.T) {
	tests := map[string]struct {
		Policy     *Policy
		Src        addr.IA
		Dst        addr.IA
		ExpPathNum int
	}{
		"one option, allow everything": {
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
		"two options, deny everything": {
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
		"two options, first: allow everything, second: allow one path": {
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
		"two options, combined": {
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
		"two options, take first": {
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
		"two options, take second": {
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
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pp := NewPathProvider(ctrl)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			paths := pp.GetPaths(test.Src, test.Dst)
			outPaths := test.Policy.Act(paths)
			assert.Equal(t, test.ExpPathNum, len(outPaths))
		})
	}
}

func TestExtends(t *testing.T) {
	tests := map[string]struct {
		Policy         *ExtPolicy
		Extended       []*ExtPolicy
		ExtendedPolicy *Policy
	}{
		"one extends, use sub acl": {
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
		"use option of extended policy": {
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
		"two extends, use sub acl and list": {
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
		"two extends, only use acl": {
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
		"three extends, use last list": {
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
		"nested extends": {
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
		"nested extends, evaluating order": {
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
		"different nested extends, evaluating order": {
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

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			pol, err := PolicyFromExtPolicy(test.Policy, test.Extended)
			if assert.NoError(t, err) {
				assert.Equal(t, test.ExtendedPolicy, pol)
			}
		})
	}

	t.Run("TestPolicy Extend not found", func(t *testing.T) {
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
		assert.Error(t, err)
	})
}

func TestSequenceConstructor(t *testing.T) {
	tests := map[string]assert.ErrorAssertionFunc{
		"0-0-0#0": assert.Error,
		"0#0#0":   assert.Error,
		"0":       assert.NoError,
		"1#0":     assert.Error,
		"1-0":     assert.NoError,
	}
	for seq, assertion := range tests {
		t.Run(seq, func(t *testing.T) {
			_, err := NewSequence(seq)
			assertion(t, err, seq)
		})
	}
}

func newSequence(t *testing.T, str string) *Sequence {
	seq, err := NewSequence(str)
	xtest.FailOnErr(t, err)
	return seq
}

type PathProvider struct {
	g *graph.Graph
}

func NewPathProvider(ctrl *gomock.Controller) PathProvider {
	return PathProvider{
		g: graph.NewDefaultGraph(ctrl),
	}
}

func (p PathProvider) GetPaths(src, dst addr.IA) PathSet {
	result := make(PathSet)
	paths := p.g.GetPaths(src.String(), dst.String())
	for _, ifids := range paths {
		pathIntfs := make([]PathInterface, 0, len(ifids))
		var key strings.Builder
		for _, ifid := range ifids {
			ia := p.g.GetParent(ifid)
			pathIntfs = append(pathIntfs, testPathIntf{ia: ia, ifid: ifid})
			key.WriteString(fmt.Sprintf("%s-%d", ia, ifid))
		}
		result[key.String()] = &testPath{interfaces: pathIntfs, key: key.String()}
	}
	return result
}

type testPath struct {
	interfaces []PathInterface
	key        string
}

func (p *testPath) Interfaces() []PathInterface {
	return p.interfaces
}

func (p *testPath) IsPartial() bool { return false }

func (p *testPath) Key() string { return p.key }

type testPathIntf struct {
	ia   addr.IA
	ifid common.IFIDType
}

func (i testPathIntf) IfId() common.IFIDType { return i.ifid }
func (i testPathIntf) IA() addr.IA           { return i.ia }

func mustHopPredicate(t *testing.T, str string) *HopPredicate {
	hp, err := HopPredicateFromString(str)
	xtest.FailOnErr(t, err)
	return hp
}
