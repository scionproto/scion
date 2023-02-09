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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/xtest"
)

func TestNewACL(t *testing.T) {
	tests := map[string]struct {
		Entries     []*ACLEntry
		ExpectedErr error
	}{
		"No entry": {
			ExpectedErr: ErrNoDefault,
		},
		"No default entry": {
			Entries: []*ACLEntry{
				{Action: Allow, Rule: mustHopPredicate(t, "1-0#0")},
			},
			ExpectedErr: ErrNoDefault,
		},
		"Entry without rule": {
			Entries: []*ACLEntry{{Action: Allow}},
		},
		"Entry with hop predicates": {
			Entries: []*ACLEntry{
				{Action: Allow, Rule: mustHopPredicate(t, "1-0#0")},
				{Action: Deny, Rule: mustHopPredicate(t, "0-0#0")},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			acl, err := NewACL(test.Entries...)
			assert.ErrorIs(t, err, test.ExpectedErr)
			if test.ExpectedErr == nil {
				assert.NotNil(t, acl)
			}
		})
	}
}

func TestACLEntryLoadFromString(t *testing.T) {
	tests := map[string]struct {
		String         string
		ACLEntry       ACLEntry
		ErrorAssertion assert.ErrorAssertionFunc
	}{
		"Allow all": {
			String: "+ 0",
			ACLEntry: ACLEntry{
				Action: Allow,
				Rule:   &HopPredicate{IfIDs: []common.IFIDType{0}},
			},
			ErrorAssertion: assert.NoError,
		},
		"Allow 1-2#3": {
			String: "+ 1-2#3",
			ACLEntry: ACLEntry{
				Action: Allow,
				Rule:   &HopPredicate{ISD: 1, AS: 2, IfIDs: []common.IFIDType{3}},
			},
			ErrorAssertion: assert.NoError,
		},
		"Allow all short": {
			String:         "+",
			ACLEntry:       ACLEntry{Action: Allow},
			ErrorAssertion: assert.NoError,
		},
		"Allow none": {
			String: "- 0",
			ACLEntry: ACLEntry{
				Action: Deny,
				Rule:   &HopPredicate{IfIDs: []common.IFIDType{0}},
			},
			ErrorAssertion: assert.NoError,
		},
		"Bad action symbol": {
			String:         "* 0",
			ACLEntry:       ACLEntry{},
			ErrorAssertion: assert.Error,
		},
		"Bad aclEntry string": {
			String:         "+ 0 0",
			ACLEntry:       ACLEntry{},
			ErrorAssertion: assert.Error,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var aclEntry ACLEntry
			err := aclEntry.LoadFromString(test.String)
			test.ErrorAssertion(t, err)
			assert.Equal(t, test.ACLEntry, aclEntry)
		})
	}
}

func TestACLEntryString(t *testing.T) {
	aclEntryString := "+ 0-0#0"
	aclEntry := &ACLEntry{Action: true, Rule: &HopPredicate{IfIDs: []common.IFIDType{0}}}
	assert.Equal(t, aclEntryString, aclEntry.String())
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
			ACL: &ACL{
				Entries: []*ACLEntry{
					{Action: Allow, Rule: mustHopPredicate(t, "0-0#0")},
					denyEntry,
				},
			},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"allow 2-0#0, deny rest": {
			ACL: &ACL{
				Entries: []*ACLEntry{
					{Action: Allow, Rule: mustHopPredicate(t, "2-0#0")},
					denyEntry,
				},
			},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"allow 2-ff00:0:212#0 and 2-ff00:0:211, deny rest": {
			ACL: &ACL{
				Entries: []*ACLEntry{
					{Action: Allow, Rule: mustHopPredicate(t, "2-ff00:0:212#0")},
					{Action: Allow, Rule: mustHopPredicate(t, "2-ff00:0:211#0")},
					denyEntry,
				},
			},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"allow 2-ff00:0:212#0, deny rest": {
			ACL: &ACL{
				Entries: []*ACLEntry{
					{Action: Allow, Rule: mustHopPredicate(t, "2-ff00:0:212#0")},
					denyEntry,
				},
			},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 0,
		},
		"deny 1-ff00:0:110#0, 1-ff00:0:120#0, allow rest": {
			ACL: &ACL{
				Entries: []*ACLEntry{
					{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:110#0")},
					{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
					allowEntry,
				},
			},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("2-ff00:0:222"),
			ExpPathNum: 2,
		},
		"deny 1-ff00:0:110#0, 1-ff00:0:120#0 and 1-ff00:0:111#2823, allow rest": {
			ACL: &ACL{
				Entries: []*ACLEntry{
					{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:110#0")},
					{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
					{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:111#2823")},
					allowEntry,
				},
			},
			Src:        xtest.MustParseIA("1-ff00:0:133"),
			Dst:        xtest.MustParseIA("2-ff00:0:222"),
			ExpPathNum: 1,
		},
		"deny ISD1, allow certain ASes": {
			ACL: &ACL{
				Entries: []*ACLEntry{
					{Action: Allow, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
					{Action: Allow, Rule: mustHopPredicate(t, "1-ff00:0:130#0")},
					{Action: Deny, Rule: mustHopPredicate(t, "1-0#0")},
					allowEntry,
				},
			},
			Src:        xtest.MustParseIA("1-ff00:0:130"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 2,
		},
		"deny ISD1, allow certain ASes - wrong oder": {
			ACL: &ACL{
				Entries: []*ACLEntry{
					{Action: Deny, Rule: mustHopPredicate(t, "1-0#0")},
					{Action: Allow, Rule: mustHopPredicate(t, "1-ff00:0:130#0")},
					{Action: Allow, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
					allowEntry,
				},
			},
			Src:        xtest.MustParseIA("1-ff00:0:130"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 0,
		},
		"nil rule should match all the paths": {
			ACL: &ACL{
				Entries: []*ACLEntry{
					{Action: Deny, Rule: nil},
					allowEntry,
				},
			},
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
	acl := &ACL{
		Entries: []*ACLEntry{
			{Action: Allow, Rule: mustHopPredicate(t, "1-0#0")},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pp := NewPathProvider(ctrl)
	paths := pp.GetPaths(xtest.MustParseIA("2-ff00:0:212"), xtest.MustParseIA("2-ff00:0:211"))
	assert.Panics(t, func() { acl.Eval(paths) })
}
