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
	"net"
	"strconv"

	"github.com/google/gopacket/layers"

	"github.com/netsec-ethz/scion/go/lib/common"
)

type CondIPv4 struct {
	Predicate IPv4Predicate
}

func NewCondIPv4(p IPv4Predicate) *CondIPv4 {
	cond := &CondIPv4{Predicate: p}
	return cond
}

func (c *CondIPv4) Eval(v *ClsPkt) bool {
	if v == nil {
		return false
	}
	pkt, ok := v.parsedPkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || pkt == nil {
		return false
	}
	return c.Predicate.Eval(pkt)
}

func (c *CondIPv4) IndentString(indent int) string {
	return spaces(indent) + fmt.Sprintf("%v", c.Predicate)
}

func (c *CondIPv4) MarshalJSON() ([]byte, error) {
	jc := make(JSONContainer)
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

type IPv4Predicate interface {
	Eval(*layers.IPv4) bool
}

type MatchSource struct {
	Net *net.IPNet
}

func (m *MatchSource) Eval(p *layers.IPv4) bool {
	return m.Net.Contains(p.SrcIP)
}

func (m *MatchSource) MarshalJSON() ([]byte, error) {
	// Pretty print subnets
	return json.Marshal(
		JSONContainer{
			"Net": m.Net.String(),
		},
	)
}

func (m *MatchSource) UnmarshalJSON(b []byte) error {
	var jc JSONContainer
	err := json.Unmarshal(b, &jc)
	if err != nil {
		return err
	}

	v, ok := jc["Net"]
	if !ok {
		return common.NewCError("MatchSource predicate lacks operand")
	}

	s, ok := v.(string)
	if !ok {
		return common.NewCError("Unable to parse MatchSource operand")
	}

	_, network, err := net.ParseCIDR(s)
	if err != nil {
		return common.NewCError("Unable to parse MatchSource operand", "err", err)
	}
	m.Net = network
	return nil
}

type MatchDestination struct {
	Net *net.IPNet
}

func (m *MatchDestination) Eval(p *layers.IPv4) bool {
	return m.Net.Contains(p.DstIP)
}

func (m *MatchDestination) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		JSONContainer{
			"Net": m.Net.String(),
		},
	)
}

func (m *MatchDestination) UnmarshalJSON(b []byte) error {
	var jc JSONContainer
	err := json.Unmarshal(b, &jc)
	if err != nil {
		return err
	}

	v, ok := jc["Net"]
	if !ok {
		return common.NewCError("MatchDestination predicate lacks operand")
	}

	s, ok := v.(string)
	if !ok {
		return common.NewCError("Unable to parse MatchDestination operand")
	}

	_, network, err := net.ParseCIDR(s)
	if err != nil {
		return common.NewCError("Unable to parse MatchDestination operand", "err", err)
	}
	m.Net = network
	return nil
}

type MatchTOS struct {
	TOS uint8
}

func (m *MatchTOS) Eval(p *layers.IPv4) bool {
	return m.TOS == p.TOS
}

func (m *MatchTOS) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		JSONContainer{
			"TOS": fmt.Sprintf("%#x", m.TOS),
		},
	)
}

func (m *MatchTOS) UnmarshalJSON(b []byte) error {
	// Format is 0x hex number in quoted string
	var jc JSONContainer
	err := json.Unmarshal(b, &jc)
	if err != nil {
		return err
	}

	v, ok := jc["TOS"]
	if !ok {
		return common.NewCError("TOS predicate lacks operand")
	}

	s, ok := v.(string)
	if !ok {
		return common.NewCError("Unable to parse TOS operand")
	}

	i, err := strconv.ParseUint(s, 0, 8)
	if err != nil {
		return common.NewCError("Unable to parse TOS operand", "err", err)
	}
	m.TOS = uint8(i)
	return nil
}
