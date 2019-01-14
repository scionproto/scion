// Copyright 2019 ETH Zurich
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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestACLEntryLoadFromString(t *testing.T) {
	testCases := []struct {
		Name     string
		String   string
		ACLEntry ACLEntry
		Error    bool
	}{
		{
			Name:     "Allow all",
			String:   "+ 0",
			ACLEntry: ACLEntry{Action: Allow, Rule: &HopPredicate{IfIDs: []common.IFIDType{0}}},
		},
		{
			Name:   "Allow 1-2#3",
			String: "+ 1-2#3",
			ACLEntry: ACLEntry{Action: Allow, Rule: &HopPredicate{ISD: 1, AS: 2,
				IfIDs: []common.IFIDType{3}}},
		},
		{
			Name:     "Allow all short",
			String:   "+",
			ACLEntry: ACLEntry{Action: Allow},
		},
		{
			Name:     "Allow none",
			String:   "- 0",
			ACLEntry: ACLEntry{Action: Deny, Rule: &HopPredicate{IfIDs: []common.IFIDType{0}}},
		},
		{
			Name:     "Bad action symbol",
			String:   "* 0",
			ACLEntry: ACLEntry{},
			Error:    true,
		},
		{
			Name:     "Bad aclEntry string",
			String:   "+ 0 0",
			ACLEntry: ACLEntry{},
			Error:    true,
		},
	}

	Convey("TestACLEntryLoadFromString", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				var aclEntry ACLEntry
				err := aclEntry.LoadFromString(tc.String)
				xtest.SoMsgError("err", err, tc.Error)
				SoMsg("aclEntry", aclEntry, ShouldResemble, tc.ACLEntry)
			})
		}
	})
}

func TestACLEntryString(t *testing.T) {
	Convey("TestACLEntryString", t, func() {
		aclEntryString := "+ 0-0#0"
		aclEntry := &ACLEntry{Action: true, Rule: &HopPredicate{IfIDs: []common.IFIDType{0}}}
		SoMsg("aclEntry", aclEntryString, ShouldResemble, aclEntry.String())
	})
}
