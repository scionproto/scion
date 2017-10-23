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

package pathmgr

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

// A PathPredicate's Eval method returns true if the slice of interfaces in
// Match is included in the AppPath parameter. Zero values in Match symbolize
// wildcard matches. For more information and examples, consult the pktcls
// documentation.
type PathPredicate struct {
	Match []sciond.PathInterface
}

func NewPathPredicate(expr string) (*PathPredicate, error) {
	var ifaces []sciond.PathInterface
	ifaceStrs := strings.Split(expr, ",")
	for _, ifaceStr := range ifaceStrs {
		iface, err := ppParseIface(ifaceStr)
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
		if ppWildcardEquals(&ifaces[i], &pp.Match[mIdx]) {
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
		desc = append(desc, fmt.Sprintf("%d-%d#%d", isdas.I, isdas.A, iface.IfID))
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
		return common.NewCError("Unable to parse PathPredicate operand", "err", err)
	}
	pp.Match = other.Match
	return nil
}

func ppParseIface(str string) (sciond.PathInterface, error) {
	tokens := strings.Split(str, "#")
	if len(tokens) != 2 {
		return sciond.PathInterface{},
			common.NewCError("Failed to parse interface spec", "value", str)
	}
	var iface sciond.PathInterface
	ia, err := addr.IAFromString(tokens[0])
	if err != nil {
		return sciond.PathInterface{}, err
	}
	iface.RawIsdas = ia.IAInt()
	ifid, err := strconv.ParseUint(tokens[1], 10, 64)
	if err != nil {
		return sciond.PathInterface{}, err
	}
	iface.IfID = ifid
	return iface, nil
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
