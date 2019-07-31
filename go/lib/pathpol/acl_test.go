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

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/common"
)

func TestNewACL(t *testing.T) {
	tests := map[string]struct {
		Entries        []*ACLEntry
		ErrorAssertion assert.ErrorAssertionFunc
	}{
		"No entry": {
			ErrorAssertion: assert.Error,
		},
		"Entry without rule": {
			Entries:        []*ACLEntry{{Action: Allow}},
			ErrorAssertion: assert.NoError,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := NewACL(test.Entries...)
			test.ErrorAssertion(t, err)
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
