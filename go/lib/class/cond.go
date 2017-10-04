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
	IndentString(indent int) string
}

var (
	_ Cond = CondAny(nil)
	_ Cond = CondAll(nil)
	_ Cond = CondBool(true)
	_ Cond = (*CondIPv4)(nil)
)

// CondAny conditions return true if all subconditions return true.
type CondAny []Cond

func NewCondAny(children ...Cond) CondAny {
	return CondAny(children)
}

func (c CondAny) Eval(v *ClsPkt) bool {
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

func (c CondAny) IndentString(indent int) string {
	result := spaces(indent) + "Any\n"
	for _, child := range c {
		result += child.IndentString(indent + 4)
	}
	return result
}

func (c CondAny) String() string {
	s := "any("
	for _, cond := range c {
		s += fmt.Sprintf("%v,", cond)
	}
	s += ")"
	return s
}

func (c CondAny) MarshalJSON() ([]byte, error) {
	// A 0 length slice serializes to an empty JSON list, as opposed to JSON
	// null. When unmarshaling, this will yield an empty slice as opposed to
	// nil. We will use this in union structs to distinguish between concrete
	// types, as only one type will be different from nil.
	childConds := make([]JSONContainer, 0)
	for _, cond := range c {
		jc := make(JSONContainer)
		jc.addTypedCond(cond)
		childConds = append(childConds, jc)
	}
	return json.Marshal(childConds)
}

func (c *CondAny) UnmarshalJSON(b []byte) error {
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

// CondAll conditions return true if at least one subcondition returns true.
type CondAll []Cond

func NewCondAll(children ...Cond) CondAll {
	return CondAll(children)
}

func (c CondAll) Eval(v *ClsPkt) bool {
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

func (c CondAll) IndentString(indent int) string {
	result := spaces(indent) + "All\n"
	for _, child := range c {
		result += child.IndentString(indent + 4)
	}
	return result
}

func (c CondAll) String() string {
	s := "any("
	for _, cond := range c {
		s += fmt.Sprintf("%v,", cond)
	}
	s += ")"
	return s
}

func (c CondAll) MarshalJSON() ([]byte, error) {
	// A 0 length slice serializes to an empty JSON list, as opposed to JSON
	// null. When unmarshaling, this will yield an empty slice as opposed to
	// nil. We will use this in union structs to distinguish between concrete
	// types, as only one type will be different from nil.
	childConds := make([]JSONContainer, 0)
	for _, cond := range c {
		jc := make(JSONContainer)
		jc.addTypedCond(cond)
		childConds = append(childConds, jc)
	}
	return json.Marshal(childConds)
}

func (c *CondAll) UnmarshalJSON(b []byte) error {
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

// CondBool contains a simple true or false value
type CondBool bool

var (
	CondTrue  CondBool = true
	CondFalse CondBool = false
)

func (c CondBool) Eval(v *ClsPkt) bool {
	return bool(c)
}

func (c CondBool) IndentString(indent int) string {
	return spaces(indent) + fmt.Sprintf("%t\n", bool(c))
}

// spaces returns a string containing n spaces
func spaces(n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += " "
	}
	return result
}
