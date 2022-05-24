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
	"encoding/json"
	"errors"
	"strings"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

var (
	// ErrNoDefault indicates that there is no default acl entry.
	ErrNoDefault = errors.New("ACL does not have a default")
)

type ACL struct {
	Entries []*ACLEntry
}

// NewACL creates a new entry and checks for the presence of a default action
func NewACL(entries ...*ACLEntry) (*ACL, error) {
	if len(entries) == 0 || !entries[len(entries)-1].Rule.matchesAll() {
		return nil, ErrNoDefault
	}
	return &ACL{Entries: entries}, nil
}

// Eval returns the set of paths that match the ACL.
func (a *ACL) Eval(paths []snet.Path) []snet.Path {
	if a == nil || len(a.Entries) == 0 {
		return paths
	}
	result := []snet.Path{}
	for _, path := range paths {
		// Check ACL
		if a.evalPath(path.Metadata()) {
			result = append(result, path)
		}
	}
	return result
}

func (a *ACL) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.Entries)
}

func (a *ACL) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &a.Entries)
}

func (a *ACL) MarshalYAML() (interface{}, error) {
	return a.Entries, nil
}

func (a *ACL) UnmarshalYAML(unmarshal func(interface{}) error) error {
	return unmarshal(&a.Entries)
}

func (a *ACL) evalPath(pm *snet.PathMetadata) ACLAction {
	for i, iface := range pm.Interfaces {
		if a.evalInterface(iface, i%2 != 0) == Deny {
			return Deny
		}
	}
	return Allow
}

func (a *ACL) evalInterface(iface snet.PathInterface, ingress bool) ACLAction {
	for _, aclEntry := range a.Entries {
		if aclEntry.Rule == nil || aclEntry.Rule.pathIFMatch(iface, ingress) {
			return aclEntry.Action
		}
	}
	panic("Default ACL action missing")
}

type ACLEntry struct {
	Action ACLAction
	Rule   *HopPredicate
}

func (ae *ACLEntry) LoadFromString(str string) error {
	var err error
	parts := strings.Split(str, " ")
	if len(parts) == 1 {
		ae.Action, err = getAction(parts[0])
		return err
	} else if len(parts) == 2 {
		ae.Action, err = getAction(parts[0])
		if err != nil {
			return err
		}
		ae.Rule, err = HopPredicateFromString(parts[1])
		return err
	}
	return serrors.New("ACLEntry has too many parts", "str", str)
}

func (ae *ACLEntry) String() string {
	str := denySymbol
	if ae.Action == Allow {
		str = allowSymbol
	}
	if ae.Rule != nil {
		str = str + " " + ae.Rule.String()
	}
	return str
}

func (ae *ACLEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal(ae.String())
}

func (ae *ACLEntry) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err != nil {
		return err
	}
	return ae.LoadFromString(str)
}

func (ae *ACLEntry) MarshalYAML() (interface{}, error) {
	return ae.String(), nil
}

func (ae *ACLEntry) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}
	return ae.LoadFromString(str)
}

func getAction(symbol string) (ACLAction, error) {
	if symbol == allowSymbol {
		return true, nil
	} else if symbol == denySymbol {
		return false, nil
	} else {
		return false, serrors.New("Bad action symbol", "action", symbol)
	}
}

// ACLAction has two options: Deny and Allow
type ACLAction bool

const (
	Deny        ACLAction = false
	Allow       ACLAction = true
	denySymbol  string    = "-"
	allowSymbol string    = "+"
)
