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
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
)

type ACL struct {
	Entries []*ACLEntry
}

// NewACLWithDefault creates a new ACL from entries, and appends a match
// anything ACL entry with defaultAction.
func NewACLWithDefault(defaultAction ACLAction, entries ...*ACLEntry) *ACL {
	defEntry := &ACLEntry{ACLAction(defaultAction), &sciond.PathInterface{}}
	return &ACL{
		Entries: append(entries, defEntry),
	}
}

// Eval returns the set of paths that match the ACL.
func (a *ACL) Eval(inputSet spathmeta.AppPathSet) spathmeta.AppPathSet {
	resultSet := make(spathmeta.AppPathSet)
	for key, path := range inputSet {
		// Check ACL
		if a.evalPath(path) {
			resultSet[key] = path
		}
	}
	return resultSet
}

func (a *ACL) evalPath(path *spathmeta.AppPath) ACLAction {
	if a == nil {
		return Allow
	}
	for _, iface := range path.Entry.Path.Interfaces {
		if a.evalInterface(iface) == Deny {
			return Deny
		}
	}
	return Allow
}

func (a *ACL) evalInterface(iface sciond.PathInterface) ACLAction {
	for _, aclEntry := range a.Entries {
		if spathmeta.PPWildcardEquals(&iface, aclEntry.Rule) {
			return aclEntry.Action
		}
	}
	return Deny
}

type ACLEntry struct {
	Action ACLAction
	Rule   *sciond.PathInterface
}

// ACLAction has two options: Deny and Allow
type ACLAction bool

const (
	Deny  ACLAction = false
	Allow ACLAction = true
)
