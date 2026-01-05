// Copyright 2017 ETH Zurich
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

package pktcls

import (
	"fmt"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Cond is used to decide which objects match a logical predicate. Types implementing Cond
// should not be marshaled directly to JSON. Instead, embed them into a Class
// and add the Class to a ClassMap; finally, marshal the entire ClassMap.
//
// Implemented logical operations include or (CondAnyOf), and (CondAllOf) and not (CondNot).
// Two conditions can be compared using their string representations.
type Cond interface {
	// Eval returns true if the Cond evaluated on v is true, false otherwise.
	Eval(v gopacket.Layer) bool
	Typer
	fmt.Stringer
}

var _ Cond = CondAnyOf{}

// CondAnyOf conditions return true if all subconditions return true.
type CondAnyOf []Cond

func NewCondAnyOf(children ...Cond) CondAnyOf {
	return CondAnyOf(children)
}

func (c CondAnyOf) Eval(v gopacket.Layer) bool {
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
	options := make([]string, 0, len(c))
	for _, cond := range c {
		options = append(options, cond.String())
	}
	return fmt.Sprintf("any(%s)", strings.Join(options, ","))
}

func (c CondAnyOf) Type() string {
	return TypeCondAnyOf
}

func (c CondAnyOf) MarshalJSON() ([]byte, error) {
	return marshalCondSlice(c)
}

func (c *CondAnyOf) UnmarshalJSON(b []byte) error {
	var err error
	*c, err = unmarshalCondSlice(b)
	return err
}

var _ Cond = CondAllOf{}

// CondAllOf conditions return true if at least one subcondition returns true.
type CondAllOf []Cond

func NewCondAllOf(children ...Cond) CondAllOf {
	return CondAllOf(children)
}

func (c CondAllOf) Eval(v gopacket.Layer) bool {
	for _, child := range c {
		if !child.Eval(v) {
			return false
		}
	}
	return true
}

func (c CondAllOf) String() string {
	args := make([]string, 0, len(c))
	for _, cond := range c {
		args = append(args, cond.String())
	}
	return fmt.Sprintf("all(%s)", strings.Join(args, ","))
}

func (c CondAllOf) Type() string {
	return TypeCondAllOf
}

func (c CondAllOf) MarshalJSON() ([]byte, error) {
	return marshalCondSlice(c)
}

func (c *CondAllOf) UnmarshalJSON(b []byte) error {
	var err error
	*c, err = unmarshalCondSlice(b)
	return err
}

var _ Cond = CondNot{}

// CondNot conditions negate the result of the subcondition.
type CondNot struct {
	Operand Cond
}

func NewCondNot(operand Cond) CondNot {
	return CondNot{Operand: operand}
}

func (c CondNot) Eval(v gopacket.Layer) bool {
	if c.Operand == nil {
		return false
	}
	return !c.Operand.Eval(v)
}

func (c CondNot) String() string {
	return fmt.Sprintf("not(%v)", c.Operand)
}

func (c CondNot) Type() string {
	return TypeCondNot
}

func (c CondNot) MarshalJSON() ([]byte, error) {
	return marshalInterface(c.Operand)
}

func (c *CondNot) UnmarshalJSON(b []byte) error {
	var err error
	c.Operand, err = unmarshalCond(b)
	return err
}

var _ Cond = CondBool(true)

// CondBool contains a true or false value, useful for debugging and testing.
type CondBool bool

var (
	CondTrue  CondBool = true
	CondFalse CondBool = false
)

func (c CondBool) Eval(v gopacket.Layer) bool {
	return bool(c)
}

func (c CondBool) Type() string {
	return TypeCondBool
}

func (c CondBool) String() string {
	return fmt.Sprintf("BOOL=%t", bool(c))
}

var _ Cond = (*CondIPv4)(nil)

// CondIPv4 conditions return true if the embedded IPv4 predicate returns true.
type CondIPv4 struct {
	Predicate IPv4Predicate
}

func NewCondIPv4(p IPv4Predicate) *CondIPv4 {
	return &CondIPv4{Predicate: p}
}

func (c *CondIPv4) Eval(v gopacket.Layer) bool {
	if c.Predicate == nil || v == nil {
		return false
	}
	t := v.LayerType()
	if t != layers.LayerTypeIPv4 {
		return false
	}

	p, ok := v.(*layers.IPv4)
	if !ok {
		return false
	}

	return c.Predicate.Eval(p)
}

func (c *CondIPv4) Type() string {
	return TypeCondIPv4
}

func (c *CondIPv4) String() string {
	if c.Predicate == nil {
		return "<nil>"
	}
	return c.Predicate.String()
}

func (c *CondIPv4) MarshalJSON() ([]byte, error) {
	return marshalInterface(c.Predicate)
}

func (c *CondIPv4) UnmarshalJSON(b []byte) error {
	var err error
	c.Predicate, err = unmarshalIPv4Predicate(b)
	return err
}

var _ Cond = (*CondPorts)(nil)

// CondPorts conditions return true if the embedded port predicate returns true.
type CondPorts struct {
	Predicate PortPredicate
}

func NewCondPorts(p PortPredicate) *CondPorts {
	return &CondPorts{Predicate: p}
}

func (c *CondPorts) Eval(v gopacket.Layer) bool {
	if c.Predicate == nil || v == nil {
		return false
	}
	// Port predicates are independent on particular L3 or L4 protocol.
	// Here we extract the ports and pass them to the embedded predicate.
	l3 := v.LayerType()
	if l3 != layers.LayerTypeIPv4 {
		return false
	}
	ipv4, ok := v.(*layers.IPv4)
	if !ok {
		return false
	}

	switch ipv4.NextLayerType() {
	case layers.LayerTypeUDP:
		udp := &layers.UDP{}
		err := udp.DecodeFromBytes(ipv4.LayerPayload(), gopacket.NilDecodeFeedback)
		if err != nil {
			return false
		}
		return c.Predicate.Eval(&Ports{
			Src: uint16(udp.SrcPort),
			Dst: uint16(udp.DstPort),
		})
	case layers.LayerTypeTCP:
		tcp := &layers.TCP{}
		err := tcp.DecodeFromBytes(ipv4.LayerPayload(), gopacket.NilDecodeFeedback)
		if err != nil {
			return false
		}
		return c.Predicate.Eval(&Ports{
			Src: uint16(tcp.SrcPort),
			Dst: uint16(tcp.DstPort),
		})
	default:
		return false
	}
}

func (c *CondPorts) Type() string {
	return TypeCondPorts
}

func (c *CondPorts) String() string {
	if c.Predicate == nil {
		return "<nil>"
	}
	return c.Predicate.String()
}

func (c *CondPorts) MarshalJSON() ([]byte, error) {
	return marshalInterface(c.Predicate)
}

func (c *CondPorts) UnmarshalJSON(b []byte) error {
	var err error
	c.Predicate, err = unmarshalPortPredicate(b)
	return err
}

const typeCondClass = "CondClass"

// CondClass conditions return true if the embedded traffic class returns true
type CondClass struct {
	TrafficClass string
}

func (c CondClass) Eval(v gopacket.Layer) bool {
	return false
}

func (c CondClass) Type() string {
	return typeCondClass
}

func (c CondClass) String() string {
	return fmt.Sprintf("cls=%s", c.TrafficClass)
}
