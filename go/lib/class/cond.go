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
	"encoding/json"
	"fmt"
)

// Cond is used to decide which packets match a class.
type Cond interface {
	Eval(*ClsPkt) bool
}

var (
	_ Cond = CondAnyOf(nil)
	_ Cond = CondAllOf(nil)
	_ Cond = CondBool(true)
	_ Cond = (*CondIPv4)(nil)
)

// CondAnyOf conditions return true if all subconditions return true.
type CondAnyOf []Cond

func NewCondAnyOf(children ...Cond) CondAnyOf {
	return CondAnyOf(children)
}

func (c CondAnyOf) Eval(v *ClsPkt) bool {
	if len(c) == 0 {
		return true
	}
	result := false
	for _, child := range c {
		result = result || child.Eval(v)
		// Shortcircuit
		if result {
			return result
		}
	}
	return result
}

func (c CondAnyOf) String() string {
	s := "any("
	for _, cond := range c {
		s += fmt.Sprintf("%v,", cond)
	}
	s += ")"
	return s
}

func (c CondAnyOf) MarshalJSON() ([]byte, error) {
	// A 0 length slice serializes to an empty JSON list, as opposed to JSON
	// null. When unmarshaling, this will yield an empty slice as opposed to
	// nil. We will use this in union structs to distinguish between concrete
	// types, as only one type will be different from nil.
	childConds := make([]jsonContainer, 0)
	for _, cond := range c {
		jc := make(jsonContainer)
		jc.addTypedCond(cond)
		childConds = append(childConds, jc)
	}
	return json.Marshal(childConds)
}

func (c *CondAnyOf) UnmarshalJSON(b []byte) error {
	var s []condUnion
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	for _, union := range s {
		cond, err := union.extractCond()
		if err != nil {
			return err
		}
		*c = append(*c, cond)
	}
	return nil
}

// CondAllOf conditions return true if at least one subcondition returns true.
type CondAllOf []Cond

func NewCondAllOf(children ...Cond) CondAllOf {
	return CondAllOf(children)
}

func (c CondAllOf) Eval(v *ClsPkt) bool {
	if len(c) == 0 {
		return true
	}
	result := true
	for _, child := range c {
		result = result && child.Eval(v)
		// Shortcircuit
		if !result {
			return result
		}
	}
	return result
}

func (c CondAllOf) String() string {
	s := "any("
	for _, cond := range c {
		s += fmt.Sprintf("%v,", cond)
	}
	s += ")"
	return s
}

func (c CondAllOf) MarshalJSON() ([]byte, error) {
	// A 0 length slice serializes to an empty JSON list, as opposed to JSON
	// null. When unmarshaling, this will yield an empty slice as opposed to
	// nil. We will use this in union structs to distinguish between concrete
	// types, as only one type will be different from nil.
	childConds := make([]jsonContainer, 0)
	for _, cond := range c {
		jc := make(jsonContainer)
		jc.addTypedCond(cond)
		childConds = append(childConds, jc)
	}
	return json.Marshal(childConds)
}

func (c *CondAllOf) UnmarshalJSON(b []byte) error {
	var s []condUnion
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	for _, union := range s {
		cond, err := union.extractCond()
		if err != nil {
			return err
		}
		*c = append(*c, cond)
	}
	return nil
}

// CondBool contains a true or false value, useful for debugging and testing.
type CondBool bool

var (
	CondTrue  CondBool = true
	CondFalse CondBool = false
)

func (c CondBool) Eval(v *ClsPkt) bool {
	return bool(c)
}
