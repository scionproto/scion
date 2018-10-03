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

package spathmeta

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sciond"
)

// A PathPredicate specifies which sequence of ASes and interfaces the packet
// must travel through; gaps in the matching are allowed.  Wildcard ISDs, ASes
// and IFIDs are specified with 0. For example, a path filtering predicate that
// only allows paths which pass through ISD1 can be created with:
//     pp, err = NewPathPredicate("1-0#0")
//
// To allow paths passing through ISD-AS 1-ff00:0:310 interface 27 and then
// ISD-AS 1-ff00:0:320 interface 95:
//     pp, err = NewPathPredicate("1-ff00:0:310#27,1-ff00:0:320#95")
type PathPredicate struct {
	Match []sciond.PathInterface
}

func NewPathPredicate(expr string) (*PathPredicate, error) {
	var ifaces []sciond.PathInterface
	ifaceStrs := strings.Split(expr, ",")
	for _, ifaceStr := range ifaceStrs {
		iface, err := sciond.NewPathInterface(ifaceStr)
		if err != nil {
			return nil, err
		}

		ifaces = append(ifaces, iface)
	}
	return &PathPredicate{Match: ifaces}, nil
}

func (pp *PathPredicate) Eval(path *sciond.PathReplyEntry) bool {
	ifaces := path.Path.Interfaces
	mIdx := 0
	for i := range ifaces {
		if PPWildcardEquals(ifaces[i], pp.Match[mIdx]) {
			mIdx += 1
			if mIdx == len(pp.Match) {
				return true
			}
		}
	}
	return false
}

func (pp *PathPredicate) String() string {
	var desc []string
	for _, iface := range pp.Match {
		isdas := iface.ISD_AS()
		desc = append(desc, fmt.Sprintf("%d-%s#%d", isdas.I, isdas.A, iface.IfID))
	}
	return strings.Join(desc, ",")
}

func (pp *PathPredicate) MarshalJSON() ([]byte, error) {
	return json.Marshal(pp.String())
}

func (pp *PathPredicate) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	other, err := NewPathPredicate(s)
	if err != nil {
		return common.NewBasicError("Unable to parse PathPredicate operand", err)
	}
	pp.Match = other.Match
	return nil
}

func PPWildcardEquals(x, y sciond.PathInterface) bool {
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
