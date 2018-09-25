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
	entries []*ACLEntry
}

func NewACL(defAllow bool, entries ...*ACLEntry) *ACL {
	pi, _ := sciond.NewPathInterface("0-0#0")
	defEntry := NewACLEntry(defAllow, &pi)
	return &ACL{
		entries: append(entries, defEntry),
	}
}

func (a *ACL) Eval(path *spathmeta.AppPath) bool {
	if a == nil {
		return true
	}

	ifaces := path.Entry.Path.Interfaces
	for i := range ifaces {
		if !a.allowIF(&ifaces[i]) {
			return false
		}
	}
	return true
}

func (a *ACL) allowIF(iface *sciond.PathInterface) bool {
	for _, aclEntry := range a.entries {
		if ppWildcardEquals(iface, aclEntry.PI) {
			if aclEntry.Type {
				return true
			} else {
				return false
			}
		}
	}
	return false
}

func ppWildcardEquals(x, y *sciond.PathInterface) bool {
	xIA, yIA := x.ISD_AS(), y.ISD_AS()
	if xIA.I != 0 && yIA.I != 0 && xIA.I != yIA.I {
		return false
	}
	if xIA.A != 0 && yIA.A != 0 && xIA.A != yIA.A {
		return false
	}
	if x.IfID != 0 && y.IfID != 0 && x.IfID != y.IfID {
		return false
	}
	return true
}

type ACLEntry struct {
	Type bool // deny: false, allow: true
	PI   *sciond.PathInterface
}

func NewACLEntry(tp bool, pi *sciond.PathInterface) *ACLEntry {
	return &ACLEntry{
		Type: tp,
		PI:   pi,
	}
}
