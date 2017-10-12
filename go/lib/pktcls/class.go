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

package pktcls

import (
	"encoding/json"
)

var (
	_ json.Marshaler   = (*Class)(nil)
	_ json.Unmarshaler = (*Class)(nil)
)

// Type Class is used to define classes of network traffic. All packets
// matching Cond are said to be part of the class. Class must not be marshaled
// to JSON directly; instead, first create a ClassMap, add the desired classes
// to it and then marshal the entire ClassMap.
type Class struct {
	name string
	Cond Cond
}

func NewClass(name string, cond Cond) *Class {
	return &Class{
		name: name,
		Cond: cond,
	}
}

func (c *Class) GetName() string {
	return c.name
}

func (c *Class) Eval(hpkt *Packet) bool {
	return c.Cond.Eval(hpkt)
}

func (c *Class) MarshalJSON() ([]byte, error) {
	return marshalInterface(c.Cond)
}

func (c *Class) UnmarshalJSON(b []byte) error {
	var err error
	c.Cond, err = unmarshalCond(b)
	return err
}
