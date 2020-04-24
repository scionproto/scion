// Copyright 2019 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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

// Package json encodes AS topology information via JSON. All types exposed by this package are
// designed to be directly marshaled to / unmarshaled from JSON.
package json

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Topology is the JSON type for the entire AS topology file.
type Topology struct {
	Timestamp      int64  `json:"Timestamp"`
	TimestampHuman string `json:"TimestampHuman"`
	TTL            uint32 `json:"TTL"`
	IA             string `json:"ISD_AS"`
	Underlay       string `json:"Overlay"`
	MTU            int    `json:"MTU"`
	// Attributes are the primary AS attributes as described in
	// https://github.com/scionproto/scion/blob/master/doc/ControlPlanePKI.md#primary-ases
	// We use the []trc.Attribute type so that we don't validate according to
	// trc.Attributes, because that contains a length 0 check which is not
	// suitable for topology.
	Attributes     []trc.Attribute        `json:"Attributes"`
	BorderRouters  map[string]*BRInfo     `json:"BorderRouters,omitempty"`
	ControlService map[string]*ServerInfo `json:"ControlService,omitempty"`
	SIG            map[string]*ServerInfo `json:"SIG,omitempty"`
}

// ServerInfo contains the information for a SCION application running in the local AS.
type ServerInfo struct {
	Addrs NATSCIONAddressMap `json:"Addrs"`
}

// NATSCIONAddressMap maps address types (e.g., "IPv4") to their values.
type NATSCIONAddressMap map[string]*NATSCIONAddress

// NATSCIONAddress contains the address information for a single server socket. It is possible for a
// server to have both a Public SCION address (i.e., globally scoped) and a Bind SCION address
// (i.e., configured on the local machine). For example, 192.0.2.1 might be the public address, and
// 10.0.0.1 might the bind address for the same socket. Note that some higher level libraries might
// not include support for bind addresses.
type NATSCIONAddress struct {
	Public FullSCIONAddress `json:"Public"`
	Bind   *Address         `json:"Bind,omitempty"`
}

// FullSCIONAddress describes a server's public SCION address and the associated underlay address.
// The address can specify a custom underlay port for this socket (note that the JSON serialization
// uses the old "overlay" term here), although usually this will be the AS default underlay port.
type FullSCIONAddress struct {
	Address
	UnderlayPort int `json:"OverlayPort,omitempty"`
}

// Address is a standard layer 3 + layer 4 address.
type Address struct {
	Addr   string `json:"Addr"`
	L4Port int    `json:"L4Port"`
}

// BRInfo contains Border Router specific information.
type BRInfo struct {
	InternalAddrs UnderlayAddressMap               `json:"InternalAddrs"`
	CtrlAddr      NATSCIONAddressMap               `json:"CtrlAddr"`
	Interfaces    map[common.IFIDType]*BRInterface `json:"Interfaces"`
}

// UnderlayAddressMap maps address types (e.g., "UDP/IPv4") to underlay address values.
type UnderlayAddressMap map[string]*NATUnderlayAddress

// NATUnderlayAddress contains the information for a single underlay (data-plane) socket. It is
// possible for an application to have both a Public Underlay address (i.e., globally scoped) and a
// Bind Underlay address (i.e., configured on the local machine). For example, 192.0.2.1 might be
// the public underlay address, and 10.0.0.1 might be the bind underlay address for the same socket.
type NATUnderlayAddress struct {
	PublicUnderlay UnderlayAddress `json:"PublicOverlay"`
	BindUnderlay   *L3Address      `json:"BindOverlay,omitempty"`
}

// BRInterface contains the information for an data-plane BR socket that is external (i.e., facing
// the neighboring AS).
type BRInterface struct {
	Underlay       string           `json:"Overlay,omitempty"`
	PublicUnderlay *UnderlayAddress `json:"PublicOverlay,omitempty"`
	BindUnderlay   *L3Address       `json:"BindOverlay,omitempty"`
	RemoteUnderlay *UnderlayAddress `json:"RemoteOverlay,omitempty"`
	Bandwidth      int              `json:"Bandwidth"`
	IA             string           `json:"ISD_AS"`
	LinkTo         string           `json:"LinkTo"`
	MTU            int              `json:"MTU"`
}

// UnderlayAddress is a standard layer 3 + layer 4 address. This is identical to the other basic
// address type in this package, except the JSON property names are different.
type UnderlayAddress struct {
	Addr         string `json:"Addr"`
	UnderlayPort int    `json:"OverlayPort,omitempty"`
}

// L3Address is a standard layer 3 address.
type L3Address struct {
	Addr string `json:"Addr"`
}

func (i ServerInfo) String() string {
	return fmt.Sprintf("Addr: %s", i.Addrs)
}

func (m NATSCIONAddressMap) String() string {
	var s []string
	for k, v := range m {
		s = append(s, fmt.Sprintf("%s: %s", k, v))
	}
	return strings.Join(s, "\n")
}

func (a NATSCIONAddress) String() string {
	var s []string
	s = append(s, fmt.Sprintf("Public: %s", a.Public))
	if a.Bind != nil {
		s = append(s, fmt.Sprintf("Bind: %s", a.Bind))
	}
	return strings.Join(s, ", ")
}

func (a FullSCIONAddress) String() string {
	return fmt.Sprintf("%s:%d/%d", a.Addr, a.L4Port, a.UnderlayPort)
}

func (a Address) String() string {
	return fmt.Sprintf("%s:%d", a.Addr, a.L4Port)
}

func (i BRInfo) String() string {
	var s []string
	s = append(s, fmt.Sprintf("Loc addrs:\n  %s\nControl addrs:\n  %s\nInterfaces:",
		i.InternalAddrs, i.CtrlAddr))
	for ifid, intf := range i.Interfaces {
		s = append(s, fmt.Sprintf("%d: %+v", ifid, intf))
	}
	return strings.Join(s, "\n")
}

func (m UnderlayAddressMap) String() string {
	var s []string
	for k, v := range m {
		s = append(s, fmt.Sprintf("%s: %s", k, v))
	}
	return strings.Join(s, "\n")
}

func (a NATUnderlayAddress) String() string {
	var s []string
	s = append(s, fmt.Sprintf("PublicOverlay: %s", a.PublicUnderlay))
	if a.BindUnderlay != nil {
		s = append(s, fmt.Sprintf("BindOverlay: %s", a.BindUnderlay))
	}
	return strings.Join(s, "\n")
}

func (a UnderlayAddress) String() string {
	return fmt.Sprintf("%s:%d", a.Addr, a.UnderlayPort)
}

func (a L3Address) String() string {
	return fmt.Sprintf("%s", a.Addr)
}

// Load parses a topology from its raw byte representation.
func Load(b common.RawBytes) (*Topology, error) {
	rt := &Topology{}
	if err := json.Unmarshal(b, rt); err != nil {
		return nil, serrors.WrapStr("unable to parse topology from JSON", err)
	}
	return rt, nil
}

// LoadFromFile parses a topology from a file.
func LoadFromFile(path string) (*Topology, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, serrors.WrapStr("unable to open topology", err, "path", path)
	}
	return Load(b)
}
