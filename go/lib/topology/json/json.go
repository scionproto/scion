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
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

// Attribute indicates the capability of a primary AS.
type Attribute string

const (
	// Authoritative indicates an authoritative AS.
	Authoritative Attribute = "authoritative"
	// AttrCore indicates a core AS.
	AttrCore Attribute = "core"
	// Issuing indicates an issuing AS.
	Issuing Attribute = "issuing"
	// Voting indicates a voting AS. A voting AS must also be a core AS.
	Voting Attribute = "voting"
)

// UnmarshalText checks that the attribute is valid. It can either be
// "authoritative", "core", "issuing", or "voting".
func (t *Attribute) UnmarshalText(b []byte) error {
	switch Attribute(b) {
	case Authoritative:
		*t = Authoritative
	case Issuing:
		*t = Issuing
	case Voting:
		*t = Voting
	case AttrCore:
		*t = AttrCore
	default:
		return serrors.New("invalid attribute", "input", string(b))
	}
	return nil
}

// Topology is the JSON type for the entire AS topology file.
type Topology struct {
	Timestamp      int64  `json:"timestamp,omitempty"`
	TimestampHuman string `json:"timestamp_human,omitempty"`
	IA             string `json:"isd_as"`
	MTU            int    `json:"mtu"`
	// Attributes are the primary AS attributes as described in
	// https://github.com/scionproto/scion/blob/master/doc/ControlPlanePKI.md#primary-ases
	Attributes          []Attribute             `json:"attributes"`
	BorderRouters       map[string]*BRInfo      `json:"border_routers,omitempty"`
	ControlService      map[string]*ServerInfo  `json:"control_service,omitempty"`
	DiscoveryService    map[string]*ServerInfo  `json:"discovery_service,omitempty"`
	HiddenSegmentLookup map[string]*ServerInfo  `json:"hidden_segment_lookup_service,omitempty"`
	HiddenSegmentReg    map[string]*ServerInfo  `json:"hidden_segment_registration_service,omitempty"`
	SIG                 map[string]*GatewayInfo `json:"sigs,omitempty"`
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

// GatewayInfo contains SCION gateway information.
type GatewayInfo struct {
	CtrlAddr   string   `json:"ctrl_addr"`
	DataAddr   string   `json:"data_addr"`
	Interfaces []uint64 `json:"allow_interfaces,omitempty"`
}

// BRInterface contains the information for an data-plane BR socket that is external (i.e., facing
// the neighboring AS).
type BRInterface struct {
	Underlay  Underlay `json:"underlay,omitempty"`
	Bandwidth int      `json:"bandwidth"`
	IA        string   `json:"isd_as"`
	LinkTo    string   `json:"link_to"`
	MTU       int      `json:"mtu"`
	BFD       *BFD     `json:"bfd,omitempty"`
}

// Underlay is the underlay information for a BR interface.
type Underlay struct {
	Public string `json:"public"`
	Remote string `json:"remote"`
	Bind   string `json:"bind,omitempty"`
}

// BFD configuration.
type BFD struct {
	Disable               bool         `json:"disable,omitempty"`
	DetectMult            uint8        `json:"detect_mult,omitempty"`
	DesiredMinTxInterval  util.DurWrap `json:"desired_min_tx_interval,omitempty"`
	RequiredMinRxInterval util.DurWrap `json:"required_min_rx_interval,omitempty"`
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
func Load(b []byte) (*Topology, error) {
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
