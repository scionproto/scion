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

	"github.com/google/gopacket/layers"
)

// Cond is used to decide which packets match a class. Types implementing Cond
// should not be marshaled directly to JSON. Instead, embed them into a Class
// and add the Class to a ClassMap; finally, marshal the entire ClassMap.
type Cond interface {
	Eval(*Packet) bool
}

var _ Cond = CondAnyOf(nil)

// CondAnyOf conditions return true if all subconditions return true.
type CondAnyOf []Cond

func NewCondAnyOf(children ...Cond) CondAnyOf {
	return CondAnyOf(children)
}

func (c CondAnyOf) Eval(v *Packet) bool {
	if len(c) == 0 {
		return true
	}
	for _, child := range c {
		if child.Eval(v) {
			return true
		}
	}
	return false
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

var _ Cond = CondAllOf(nil)

// CondAllOf conditions return true if at least one subcondition returns true.
type CondAllOf []Cond

func NewCondAllOf(children ...Cond) CondAllOf {
	return CondAllOf(children)
}

func (c CondAllOf) Eval(v *Packet) bool {
	for _, child := range c {
		if !child.Eval(v) {
			return false
		}
	}
	return true
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

var _ Cond = CondBool(true)

// CondBool contains a true or false value, useful for debugging and testing.
type CondBool bool

var (
	CondTrue  CondBool = true
	CondFalse CondBool = false
)

var _ Cond = (*CondIPv4)(nil)

func (c CondBool) Eval(v *Packet) bool {
	return bool(c)
}

// CondIPv4 conditions return true if the embedded IPv4 predicate returns true.
type CondIPv4 struct {
	Predicate IPv4Predicate
}

func NewCondIPv4(p IPv4Predicate) *CondIPv4 {
	return &CondIPv4{Predicate: p}
}

func (c *CondIPv4) Eval(v *Packet) bool {
	if v == nil {
		return false
	}
	pkt, ok := v.parsedPkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || pkt == nil {
		return false
	}
	return c.Predicate.Eval(pkt)
}

func (c *CondIPv4) MarshalJSON() ([]byte, error) {
	jc := make(jsonContainer)
	err := jc.addTypedPredicate(c.Predicate)
	if err != nil {
		return nil, err
	}
	return json.Marshal(jc)
}

func (c *CondIPv4) UnmarshalJSON(b []byte) error {
	var u predicateUnion
	err := json.Unmarshal(b, &u)
	if err != nil {
		return err
	}
	c.Predicate = u.extractPredicate()
	return nil
}
