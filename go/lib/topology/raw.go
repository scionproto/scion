// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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
	BorderRouters      map[string]*RawBRInfo  `json:",omitempty"`
	ZookeeperService   map[int]*RawAddrPort   `json:",omitempty"`
	BeaconService      map[string]*RawSrvInfo `json:",omitempty"`
	CertificateService map[string]*RawSrvInfo `json:",omitempty"`
	PathService        map[string]*RawSrvInfo `json:",omitempty"`
	SibraService       map[string]*RawSrvInfo `json:",omitempty"`
	RainsService       map[string]*RawSrvInfo `json:",omitempty"`
	SIG                map[string]*RawSrvInfo `json:",omitempty"`
	DiscoveryService   map[string]*RawSrvInfo `json:",omitempty"`
}

type RawSrvInfo struct {
	Addrs RawAddrMap
}

func (ras RawSrvInfo) String() string {
	return fmt.Sprintf("Addr: %s", ras.Addrs)
}

type RawAddrMap map[string]*RawPubBindOverlay

func (ram RawAddrMap) ToTopoAddr(ot overlay.Type) (t *TopoAddr, err error) {
	return topoAddrFromRAM(ram, ot)
}

func (ram RawAddrMap) String() string {
	var s []string
	for k, v := range ram {
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

// Since Public addresses may be associated with an Overlay port, extend the
// structure used for Bind addresses.
type RawAddrPortOverlay struct {
	RawAddrPort
	OverlayPort int `json:",omitempty"`
}

func (a RawAddrPortOverlay) String() string {
	return fmt.Sprintf("%s:%d/%d", a.Addr, a.L4Port, a.OverlayPort)
}

type RawAddrPort struct {
	Addr   string
	L4Port int
}

func (a RawAddrPort) String() string {
	return fmt.Sprintf("%s:%d", a.Addr, a.L4Port)
}

// RawBRInfo contains Border Router specific information.
type RawBRInfo struct {
	InternalAddrs RawBRAddrMap
	CtrlAddr      RawAddrMap
	Interfaces    map[common.IFIDType]*RawBRIntf
}

func (b RawBRInfo) String() string {
	var s []string
	s = append(s, fmt.Sprintf("Loc addrs:\n  %s\nControl addrs:\n  %s\nInterfaces:",
		b.InternalAddrs, b.CtrlAddr))
	for ifid, intf := range b.Interfaces {
		s = append(s, fmt.Sprintf("%d: %+v", ifid, intf))
	}
	return strings.Join(s, "\n")
}

type RawBRAddrMap map[string]*RawOverlayBind

func (roa RawBRAddrMap) ToTopoBRAddr(ot overlay.Type) (t *TopoBRAddr, err error) {
	return topoBRAddrFromRBRAM(roa, ot)
}

func (roa RawBRAddrMap) String() string {
	var s []string
	for k, v := range roa {
		s = append(s, fmt.Sprintf("%s: %s", k, v))
	}
	return strings.Join(s, "\n")
}

type RawOverlayBind struct {
	PublicOverlay RawAddrOverlay
	BindOverlay   *RawAddr `json:",omitempty"`
}

func (b RawOverlayBind) String() string {
	var s []string
	s = append(s, fmt.Sprintf("PublicOverlay: %s", b.PublicOverlay))
	if b.BindOverlay != nil {
		s = append(s, fmt.Sprintf("BindOverlay: %s", b.BindOverlay))
	}
	return strings.Join(s, "\n")
}

type RawBRIntf struct {
	Overlay       string          `json:",omitempty"`
	PublicOverlay *RawAddrOverlay `json:",omitempty"`
	BindOverlay   *RawAddr        `json:",omitempty"`
	RemoteOverlay *RawAddrOverlay `json:",omitempty"`
	Bandwidth     int
	ISD_AS        string
	LinkTo        string
	MTU           int
}

// Convert a RawBRIntf struct (filled from JSON) to a TopoBRAddr (used by Go code)
func (b RawBRIntf) localTopoBRAddr(o overlay.Type) (*TopoBRAddr, error) {
	rbram := make(RawBRAddrMap)
	rbram[o.ToIP().String()] = &RawOverlayBind{
		PublicOverlay: *b.PublicOverlay,
		BindOverlay:   b.BindOverlay,
	}
	return topoBRAddrFromRBRAM(rbram, o)
}

// make an OverlayAddr object from a BR interface Remote entry
func (b RawBRIntf) remoteBRAddr(o overlay.Type) (*overlay.OverlayAddr, error) {
	l3 := addr.HostFromIPStr(b.RemoteOverlay.Addr)
	if l3 == nil {
		return nil, common.NewBasicError("Could not parse remote IP from string", nil,
			"ip", b.RemoteOverlay.Addr)
	}
	if !o.IsUDP() && (b.RemoteOverlay.OverlayPort != 0) {
		return nil, common.NewBasicError(ErrOverlayPort, nil, "addr", b.RemoteOverlay)
	}
	var l4 addr.L4Info
	if o.IsUDP() {
		l4 = addr.NewL4UDPInfo(uint16(b.RemoteOverlay.OverlayPort))
	}
	return overlay.NewOverlayAddr(l3, l4)
}

type RawAddrOverlay struct {
	Addr        string
	OverlayPort int `json:",omitempty"`
}

func (a RawAddrOverlay) String() string {
	return fmt.Sprintf("%s:%d", a.Addr, a.OverlayPort)
}

type RawAddr struct {
	Addr string
}

func (a RawAddr) String() string {
	return fmt.Sprintf("%s", a.Addr)
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
