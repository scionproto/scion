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

package class

import (
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/common"
)

// This package makes extensive use of serialized interfaces. This requires
// special handling during marshaling and unmarshaling to take concrete types
// into account. During marshaling, addTyped* methods are used to populate a
// jsonContainer, which is a map with concrete type names pointing to
// actual structs. For example, when we marshal CondAnyOf which implements
// interface Cond, we add to jsonContainer key "CondAnyOf" with the value
// containing the actual struct.
//
// During unmarshaling, whenever we expect an interface type we unmarshal to a
// fake intermediate structure which contains fields for all possible concrete
// types. For example, CondUnion includes a pointer to each type that implements
// Cond. When unmarshaled, only one field is populated, and the Extract* method
// is called to return an interface value containing the concrete type.
//
// Type embedding is used to unmarshal objects that contain multiple fields, at
// least one of which is an interface. The Go JSON unmarshaler populates the
// correct field of the embedded type, which we later use to construct the
// actual object. For an example, see the unmarshalling code for Class.
//
// When *Union is unmarshaled (e.g., condUnion), only the field corresponding
// to the correct type is populated. Then extract* (e.g., extratCond) is called
// to retrieve the populated field.
type jsonContainer map[string]interface{}

func (jc jsonContainer) addTypedCond(c Cond) error {
	switch v := c.(type) {
	case CondAllOf:
		jc["CondAllOf"] = v
	case CondAnyOf:
		jc["CondAnyOf"] = v
	case CondBool:
		jc["CondBool"] = v
	case *CondIPv4:
		jc["CondIPv4"] = v
	default:
		return common.NewCError("Unknown cond type", "type", fmt.Sprintf("%T", c))
	}
	return nil
}

type condUnion struct {
	CondAllOf *CondAllOf
	CondAnyOf *CondAnyOf
	CondIPv4  *CondIPv4
	CondBool  *CondBool
}

func (u *condUnion) extractCond() (Cond, error) {
	if u.CondAllOf != nil {
		// Dereference to retrieve reference
		return *u.CondAllOf, nil
	}
	if u.CondAnyOf != nil {
		// Dereference to retrieve reference
		return *u.CondAnyOf, nil
	}
	if u.CondIPv4 != nil {
		// Return pointer directly
		return u.CondIPv4, nil
	}
	if u.CondBool != nil {
		// Dereference to retrieve bool
		return *u.CondBool, nil
	}
	return nil, common.NewCError("No valid condition found")
}

func (jc jsonContainer) addTypedAction(a Action) error {
	switch v := a.(type) {
	case *ActionFilterPaths:
		jc["ActionFilterPaths"] = v
	default:
		return common.NewCError("Unknown action type", "type", fmt.Sprintf("%T", a))
	}
	return nil
}

type actionUnion struct {
	ActionFilterPaths *ActionFilterPaths
}

func (u *actionUnion) extractAction(name string) (Action, error) {
	if u.ActionFilterPaths != nil {
		u.ActionFilterPaths.Name = name
		return u.ActionFilterPaths, nil
	}
	return nil, common.NewCError("No valid action found")
}

func (jc jsonContainer) addTypedPredicate(p IPv4Predicate) error {
	switch v := p.(type) {
	case *IPv4MatchSource:
		jc["MatchSource"] = v
	case *IPv4MatchDestination:
		jc["MatchDestination"] = v
	case *IPv4MatchToS:
		jc["MatchTOS"] = v
	default:
		return common.NewCError("Unknown predicate type", "type", fmt.Sprintf("%T", p))
	}
	return nil
}

type predicateUnion struct {
	MatchTOS         *IPv4MatchToS
	MatchDestination *IPv4MatchDestination
	MatchSource      *IPv4MatchSource
}

func (u *predicateUnion) extractPredicate() IPv4Predicate {
	if u.MatchTOS != nil {
		return u.MatchTOS
	}
	if u.MatchDestination != nil {
		return u.MatchDestination
	}
	if u.MatchSource != nil {
		return u.MatchSource
	}
	return nil
}
