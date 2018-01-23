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
	"fmt"
	"net"
	"strconv"

	"github.com/google/gopacket/layers"

	"github.com/netsec-ethz/scion/go/lib/common"
)

// IPv4Predicate describes a single test on various IPv4 packet fields.
type IPv4Predicate interface {
	// Eval returns true if the IPv4 packet matched the predicate
	Eval(*layers.IPv4) bool
	Typer
}

var _ IPv4Predicate = (*IPv4MatchSource)(nil)

// IPv4MatchSource checks whether the source IPv4 address is contained in Net.
type IPv4MatchSource struct {
	Net *net.IPNet
}

func (m *IPv4MatchSource) Type() string {
	return "MatchSource"
}

func (m *IPv4MatchSource) Eval(p *layers.IPv4) bool {
	return m.Net.Contains(p.SrcIP)
}

func (m *IPv4MatchSource) MarshalJSON() ([]byte, error) {
	// Pretty print subnets
	return json.Marshal(
		jsonContainer{
			"Net": m.Net.String(),
		},
	)
}

func (m *IPv4MatchSource) UnmarshalJSON(b []byte) error {
	var jc jsonContainer
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

var _ IPv4Predicate = (*IPv4MatchDestination)(nil)

// IPv4MatchDestination checks whether the destination IPv4 address is contained in
// Net.
type IPv4MatchDestination struct {
	Net *net.IPNet
}

func (m *IPv4MatchDestination) Type() string {
	return "MatchDestination"
}

func (m *IPv4MatchDestination) Eval(p *layers.IPv4) bool {
	return m.Net.Contains(p.DstIP)
}

func (m *IPv4MatchDestination) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		jsonContainer{
			"Net": m.Net.String(),
		},
	)
}

func (m *IPv4MatchDestination) UnmarshalJSON(b []byte) error {
	var jc jsonContainer
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

var _ IPv4Predicate = (*IPv4MatchToS)(nil)

// IPv4MatchToS checks whether the ToS field matches.
type IPv4MatchToS struct {
	TOS uint8
}

func (m *IPv4MatchToS) Type() string {
	return "MatchToS"
}

func (m *IPv4MatchToS) Eval(p *layers.IPv4) bool {
	return m.TOS == p.TOS
}

func (m *IPv4MatchToS) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		jsonContainer{
			"TOS": fmt.Sprintf("%#x", m.TOS),
		},
	)
}

func (m *IPv4MatchToS) UnmarshalJSON(b []byte) error {
	// Format is 0x hex number in quoted string
	var jc jsonContainer
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
