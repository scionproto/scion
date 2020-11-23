// Copyright 2020 Anapaya Systems
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
)

// Ports represents source and destination ports, irrespective of the
// specific L3 and L4 protocol.
type Ports struct {
	Src uint16
	Dst uint16
}

// PortPredicate describes a single test on port fields.
type PortPredicate interface {
	// Eval returns true if the packet matched the predicate
	Eval(*Ports) bool
	Typer
	fmt.Stringer
}

var _ PortPredicate = (*PortMatchSource)(nil)

// PortMatchSource checks whether the source port is within the specified range.
type PortMatchSource struct {
	MinPort uint16
	MaxPort uint16
}

func (m *PortMatchSource) Type() string {
	return "MatchSourcePort"
}

func (m *PortMatchSource) Eval(p *Ports) bool {
	return p.Src >= m.MinPort && p.Src <= m.MaxPort
}

func (m *PortMatchSource) String() string {
	return fmt.Sprintf("srcport=%d-%d", m.MinPort, m.MaxPort)
}

func (m *PortMatchSource) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		jsonContainer{
			"MinPort": fmt.Sprintf("%d", m.MinPort),
			"MaxPort": fmt.Sprintf("%d", m.MaxPort),
		},
	)
}

func (m *PortMatchSource) UnmarshalJSON(b []byte) error {
	minPort, err := unmarshalUintField(b, "MatchSourcePort", "MinPort", 16)
	if err != nil {
		return err
	}
	maxPort, err := unmarshalUintField(b, "MatchSourcePort", "MaxPort", 16)
	if err != nil {
		return err
	}
	m.MinPort = uint16(minPort)
	m.MaxPort = uint16(maxPort)
	return nil
}

var _ PortPredicate = (*PortMatchDestination)(nil)

// PortMatchDestination checks whether the destination port is within the specified range.
type PortMatchDestination struct {
	MinPort uint16
	MaxPort uint16
}

func (m *PortMatchDestination) Type() string {
	return "MatchDestinationPort"
}

func (m *PortMatchDestination) Eval(p *Ports) bool {
	return p.Dst >= m.MinPort && p.Dst <= m.MaxPort
}

func (m *PortMatchDestination) String() string {
	return fmt.Sprintf("dstport=%d-%d", m.MinPort, m.MaxPort)
}

func (m *PortMatchDestination) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		jsonContainer{
			"MinPort": fmt.Sprintf("%d", m.MinPort),
			"MaxPort": fmt.Sprintf("%d", m.MaxPort),
		},
	)
}

func (m *PortMatchDestination) UnmarshalJSON(b []byte) error {
	minPort, err := unmarshalUintField(b, "MatchDestinationPort", "MinPort", 16)
	if err != nil {
		return err
	}
	maxPort, err := unmarshalUintField(b, "MatchDestinationPort", "MaxPort", 16)
	if err != nil {
		return err
	}
	m.MinPort = uint16(minPort)
	m.MaxPort = uint16(maxPort)
	return nil
}
