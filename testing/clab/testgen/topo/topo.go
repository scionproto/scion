// Copyright 2026 Anapaya Systems
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

// Package topo parses and validates the testgen topology description file.
//
// The format mirrors the legacy topogen/.topo file and is explicitly NOT a
// stable API. A file describes a set of ASes (keyed by ISD-AS) and the links
// between them. Link endpoints use a compact notation such as
// "1-ff00:0:120-A#6" parsed into an [Endpoint].
package topo

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/iface"
)

// DefaultMTU is the MTU assigned to ASes and links that do not specify one.
// It mirrors the legacy topology generator (1500 - 20 (IP) - 8 (UDP)).
const DefaultMTU = 1472

// MinMTU is the smallest MTU SCION permits.
const MinMTU = 1280

// Topo is the parsed topology description.
type Topo struct {
	ASes  map[addr.IA]ASEntry `yaml:"ASes"`
	Links []Link              `yaml:"links"`
}

// ASEntry holds the attributes of a single AS.
type ASEntry struct {
	Core          bool         `yaml:"core"`
	Voting        bool         `yaml:"voting"`
	Authoritative bool         `yaml:"authoritative"`
	Issuing       bool         `yaml:"issuing"`
	CertIssuer    addr.IA      `yaml:"cert_issuer"`
	MTU           int          `yaml:"mtu"`
	Underlay      UnderlayType `yaml:"underlay"`
}

// Link is a directed edge from A to B with the relationship expressed from A's
// point of view (LinkAtoB).
type Link struct {
	A        Endpoint     `yaml:"a"`
	B        Endpoint     `yaml:"b"`
	LinkAtoB LinkType     `yaml:"linkAtoB"`
	MTU      int          `yaml:"mtu"`
	Underlay UnderlayType `yaml:"underlay"`
	BW       int          `yaml:"bw"` // accepted for compatibility, currently unused
}

// Endpoint is one side of a link. It is parsed from the compact notation
// "<ISD-AS>[-<BR>]#<IfID>[,<Addr>]", e.g. "1-ff00:0:120-A#6".
type Endpoint struct {
	IA   addr.IA  // 1-ff00:0:120
	BR   string   // "A": optional border-router group tag (empty if absent)
	IfID iface.ID // 6
	Addr string   // optional explicit underlay address (for external ASes)
}

// UnmarshalYAML implements yaml.Unmarshaler for the compact endpoint notation.
func (e *Endpoint) UnmarshalYAML(unmarshal func(any) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	return e.parse(raw)
}

func (e *Endpoint) parse(raw string) error {
	rest := raw
	// Optional trailing address: "...#6,127.0.0.1:50000".
	if idx := strings.IndexByte(rest, ','); idx >= 0 {
		e.Addr = strings.TrimSpace(rest[idx+1:])
		rest = rest[:idx]
	}
	idx := strings.IndexByte(rest, '#')
	if idx < 0 {
		return serrors.New("endpoint missing interface id", "value", raw)
	}
	ifStr := strings.TrimSpace(rest[idx+1:])
	id, err := strconv.ParseUint(ifStr, 10, 64)
	if err != nil {
		return serrors.Wrap("parsing interface id", err, "value", raw)
	}
	e.IfID = iface.ID(id)

	iaPart := strings.TrimSpace(rest[:idx])
	// Optional border-router tag follows the AS, separated by '-'. The IA
	// itself contains a single '-' (ISD-AS), so the BR tag is anything after a
	// second '-'.
	if first := strings.IndexByte(iaPart, '-'); first >= 0 {
		if second := strings.IndexByte(iaPart[first+1:], '-'); second >= 0 {
			tagIdx := first + 1 + second
			e.BR = iaPart[tagIdx+1:]
			iaPart = iaPart[:tagIdx]
		}
	}
	ia, err := addr.ParseIA(iaPart)
	if err != nil {
		return serrors.Wrap("parsing ISD-AS", err, "value", raw)
	}
	e.IA = ia
	return nil
}

// String renders the endpoint back into its compact notation.
func (e Endpoint) String() string {
	var b strings.Builder
	b.WriteString(e.IA.String())
	if e.BR != "" {
		b.WriteString("-")
		b.WriteString(e.BR)
	}
	fmt.Fprintf(&b, "#%d", e.IfID)
	if e.Addr != "" {
		b.WriteString(",")
		b.WriteString(e.Addr)
	}
	return b.String()
}

// LinkType is the relationship of a link as seen from endpoint A.
type LinkType string

const (
	Core   LinkType = "CORE"
	Parent LinkType = "PARENT"
	Child  LinkType = "CHILD"
	Peer   LinkType = "PEER"
)

// UnmarshalYAML implements yaml.Unmarshaler, normalizing case.
func (lt *LinkType) UnmarshalYAML(unmarshal func(any) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	switch LinkType(strings.ToUpper(raw)) {
	case Core, Parent, Child, Peer:
		*lt = LinkType(strings.ToUpper(raw))
		return nil
	default:
		return serrors.New("invalid link type", "value", raw)
	}
}

// UnderlayType identifies the transport used by a link or AS-internal network.
type UnderlayType string

const (
	UDPIPv4 UnderlayType = "UDP/IPv4"
	UDPIPv6 UnderlayType = "UDP/IPv6"
)

// UnmarshalYAML implements yaml.Unmarshaler with a sane default.
func (u *UnderlayType) UnmarshalYAML(unmarshal func(any) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	switch UnderlayType(raw) {
	case UDPIPv4, UDPIPv6:
		*u = UnderlayType(raw)
		return nil
	default:
		return serrors.New("invalid underlay", "value", raw)
	}
}

// OrDefault returns the underlay, defaulting to UDP/IPv4 when unset.
func (u UnderlayType) OrDefault() UnderlayType {
	if u == "" {
		return UDPIPv4
	}
	return u
}

// IsIPv6 reports whether the underlay is IPv6 based.
func (u UnderlayType) IsIPv6() bool {
	return u.OrDefault() == UDPIPv6
}
