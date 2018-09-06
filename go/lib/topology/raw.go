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

package topology

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
)

const CfgName = "topology.json"

const (
	ErrorOpen    = "Unable to open topology"
	ErrorParse   = "Unable to parse topology from JSON"
	ErrorConvert = "Unable to convert RawTopo to Topo"
)

// Structures directly filled from JSON

// RawTopo is used to un/marshal from/to JSON and should usually not be used by
// Go code directly. Use Topo (from lib/topology/topology.go) instead.
type RawTopo struct {
	Timestamp          int64
	TimestampHuman     string
	ISD_AS             string
	Overlay            string
	MTU                int
	Core               bool
	BorderRouters      map[string]*RawBRInfo `json:",omitempty"`
	ZookeeperService   map[int]*RawAddrPort  `json:",omitempty"`
	BeaconService      map[string]RawAddrMap `json:",omitempty"`
	CertificateService map[string]RawAddrMap `json:",omitempty"`
	PathService        map[string]RawAddrMap `json:",omitempty"`
	SibraService       map[string]RawAddrMap `json:",omitempty"`
	RainsService       map[string]RawAddrMap `json:",omitempty"`
	DiscoveryService   map[string]RawAddrMap `json:",omitempty"`
}

type RawBRInfo struct {
	InternalAddr RawAddrMap
	Interfaces   map[common.IFIDType]*RawBRIntf
}

func (b RawBRInfo) String() string {
	var s []string
	s = append(s, fmt.Sprintf("Loc addr:\n  %s\nInterfaces:", b.InternalAddr))
	for ifid, intf := range b.Interfaces {
		s = append(s, fmt.Sprintf("%d: %+v", ifid, intf))
	}
	return strings.Join(s, "\n")
}

type RawBRIntf struct {
	Overlay   string       `json:",omitempty"`
	Bind      *RawAddrPort `json:",omitempty"`
	Public    *RawAddrPort `json:",omitempty"`
	Remote    *RawAddrPort `json:",omitempty"`
	Bandwidth int
	ISD_AS    string
	LinkTo    string
	MTU       int
}

// Convert a RawBRIntf struct (filled from JSON) to a TopoAddr (used by Go code)
func (b RawBRIntf) localTopoAddr(o overlay.Type) (*TopoAddr, error) {
	ram := make(RawAddrMap)
	rpbo := &RawPubBindOverlay{
		Public: RawAddrPortOverlay{RawAddrPort: *b.Public},
		Bind:   b.Bind,
	}
	if o.IsUDP() {
		rpbo.Public.OverlayPort = b.Public.L4Port
	}
	ram[o.ToIP().String()] = rpbo
	return ram.ToTopoAddr(o)
}

// make an OverlayAddr object from a BR interface Remote entry
func (b RawBRIntf) remoteAddr(o overlay.Type) (*overlay.OverlayAddr, error) {
	ip := net.ParseIP(b.Remote.Addr)
	if ip == nil {
		return nil, common.NewBasicError("Could not parse remote IP from string", nil,
			"ip", b.Remote.Addr)
	}
	l3 := addr.HostFromIP(ip)
	var l4 addr.L4Info
	if o.IsUDP() {
		l4 = addr.NewL4UDPInfo(uint16(b.Remote.L4Port))
	}
	return overlay.NewOverlayAddr(l3, l4)
}

type RawAddrMap map[string]*RawPubBindOverlay

func (s RawAddrMap) ToTopoAddr(ot overlay.Type) (t *TopoAddr, err error) {
	return topoAddrFromRAM(s, ot)
}

func (rai RawAddrMap) String() string {
	var s []string
	for k, v := range rai {
		s = append(s, fmt.Sprintf("%s: %s", k, v))
	}
	return strings.Join(s, "\n")
}

type RawPubBindOverlay struct {
	Public RawAddrPortOverlay
	Bind   *RawAddrPort `json:",omitempty"`
}

func (rpbo RawPubBindOverlay) String() string {
	var s []string
	s = append(s, fmt.Sprintf("Public: %s", rpbo.Public))
	if rpbo.Bind != nil {
		s = append(s, fmt.Sprintf("Bind: %s", rpbo.Bind))
	}
	return strings.Join(s, ", ")

}

type RawAddrPort struct {
	Addr   string
	L4Port int
}

func (a RawAddrPort) String() string {
	return fmt.Sprintf("%s:%d", a.Addr, a.L4Port)
}

// Since Public addresses may be associated with an Overlay port, extend the
// structure used for Bind addresses.
type RawAddrPortOverlay struct {
	RawAddrPort
	OverlayPort int `json:",omitempty"`
}

func (a RawAddrPortOverlay) String() string {
	return fmt.Sprintf("%s:%d/%d", a.Addr, a.L4Port, a.OverlayPort)
}

func Load(b common.RawBytes) (*Topo, error) {
	rt := &RawTopo{}
	if err := json.Unmarshal(b, rt); err != nil {
		return nil, common.NewBasicError(ErrorParse, err)
	}
	ct, err := TopoFromRaw(rt)
	if err != nil {
		return nil, common.NewBasicError(ErrorConvert, err)
	}
	return ct, nil
}

func LoadFromFile(path string) (*Topo, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, common.NewBasicError(ErrorOpen, err, "path", path)
	}
	return Load(b)
}

func LoadRaw(b common.RawBytes) (*RawTopo, error) {
	rt := &RawTopo{}
	if err := json.Unmarshal(b, rt); err != nil {
		return nil, common.NewBasicError(ErrorParse, err)
	}
	return rt, nil
}

func LoadRawFromFile(path string) (*RawTopo, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, common.NewBasicError(ErrorOpen, err, "path", path)
	}
	return LoadRaw(b)
}
