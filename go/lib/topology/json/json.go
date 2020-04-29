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
	Timestamp      int64  `json:"timestamp,omitempty"`
	TimestampHuman string `json:"timestamp_human,omitempty"`
	IA             string `json:"isd_as"`
	MTU            int    `json:"mtu"`
	// Attributes are the primary AS attributes as described in
	// https://github.com/scionproto/scion/blob/master/doc/ControlPlanePKI.md#primary-ases
	// We use the []trc.Attribute type so that we don't validate according to
	// trc.Attributes, because that contains a length 0 check which is not
	// suitable for topology.
	Attributes     []trc.Attribute        `json:"attributes"`
	BorderRouters  map[string]*BRInfo     `json:"border_routers,omitempty"`
	ControlService map[string]*ServerInfo `json:"control_service,omitempty"`
	SIG            map[string]*ServerInfo `json:"sigs,omitempty"`
}

// ServerInfo contains the information for a SCION application running in the local AS.
type ServerInfo struct {
	Addr string `json:"addr"`
}

// BRInfo contains Border Router specific information.
type BRInfo struct {
	InternalAddr string                           `json:"internal_addr"`
	CtrlAddr     string                           `json:"ctrl_addr"`
	Interfaces   map[common.IFIDType]*BRInterface `json:"interfaces"`
}

// BRInterface contains the information for an data-plane BR socket that is external (i.e., facing
// the neighboring AS).
type BRInterface struct {
	Underlay  Underlay `json:"underlay,omitempty"`
	Bandwidth int      `json:"bandwidth"`
	IA        string   `json:"isd_as"`
	LinkTo    string   `json:"link_to"`
	MTU       int      `json:"mtu"`
}

// Underlay is the underlay information for a BR interface.
type Underlay struct {
	Public string `json:"public"`
	Remote string `json:"remote"`
	Bind   string `json:"bind,omitempty"`
}

func (i ServerInfo) String() string {
	return fmt.Sprintf("Addr: %s", i.Addr)
}

func (i BRInfo) String() string {
	var s []string
	s = append(s, fmt.Sprintf("Loc addrs:\n  %s\nControl addr:\n  %s\nInterfaces:",
		i.InternalAddr, i.CtrlAddr))
	for ifid, intf := range i.Interfaces {
		s = append(s, fmt.Sprintf("%d: %+v", ifid, intf))
	}
	return strings.Join(s, "\n")
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
