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
	BorderRouters      map[string]*RawBRInfo  `json:",omitempty"`
	ZookeeperService   map[int]*RawAddrPort   `json:",omitempty"`
	BeaconService      map[string]*RawSrvInfo `json:",omitempty"`
	CertificateService map[string]*RawSrvInfo `json:",omitempty"`
	PathService        map[string]*RawSrvInfo `json:",omitempty"`
	SibraService       map[string]*RawSrvInfo `json:",omitempty"`
	RainsService       map[string]*RawSrvInfo `json:",omitempty"`
	DiscoveryService   map[string]*RawSrvInfo `json:",omitempty"`
}

type RawSrvInfo struct {
	Addrs RawAddrMap
}

func (ras RawSrvInfo) String() string {
	return fmt.Sprintf("Addr: %s", ras.Addrs)
}

type RawBRInfo struct {
	InternalAddr *RawBRAddrMap
	CtrlAddr     *RawAddrMap
	Interfaces   map[common.IFIDType]RawBRIntf
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

func (roa RawBRAddrMap) ToTopoAddr(ot overlay.Type) (t *TopoAddr, err error) {
	return topoAddrFromRaw(roa, ot)
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
	BindOverlay   RawAddr `json:",omitempty"`
}

func (s RawBRIntAddr) intTopoAddr(ot overlay.Type) (*TopoAddr, error) {
	t := &TopoAddr{Overlay: ot}
	// Public addresses
	for _, pub := range s.PublicOverlay {
		if ot.IsUDP() == (pub.OverlayPort == 0) {
			return nil, common.NewBasicError(ErrOverlayPort, nil, "addr", pub)
		}
		ip := net.ParseIP(pub.Addr)
		if ip == nil {
			return nil, common.NewBasicError(ErrInvalidPub, nil, "addr", s, "ip", pub.Addr)
		}
		var ol4 addr.L4Info
		if ot.IsUDP() {
			ol4 = addr.NewL4UDPInfo(uint16(pub.OverlayPort))
		}
		if ip.To4() != nil {
			if t.IPv4 != nil {
				return nil, common.NewBasicError(ErrTooManyPubV4, nil, "addr", s)
			}
			t.IPv4 = &pubBindAddr{}
			t.IPv4.overlay, _ = overlay.NewOverlayAddr(addr.HostIPv4(ip), ol4)
		} else {
			if t.IPv6 != nil {
				return nil, common.NewBasicError(ErrTooManyPubV6, nil, "addr", s)
			}
			t.IPv6 = &pubBindAddr{}
			t.IPv6.overlay, _ = overlay.NewOverlayAddr(addr.HostIPv6(ip), ol4)
		}
	}
	// Bind Addresses
	for _, bind := range s.BindOverlay {
		ip := net.ParseIP(bind.Addr)
		if ip == nil {
			return nil, common.NewBasicError(ErrInvalidBind, nil, "addr", s, "ip", bind.Addr)
		}
		if ip.To4() != nil {
			if t.IPv4 == nil {
				return nil, common.NewBasicError(ErrBindWithoutPubV4, nil, "addr", s, "ip", bind.Addr)
			}
			if t.IPv4.bind != nil {
				return nil, common.NewBasicError(ErrTooManyBindV4, nil, "addr", s)
			}
			t.IPv4.bind = &addr.AppAddr{L3: addr.HostIPv4(ip), L4: t.IPv4.overlay.L4()}
		} else {
			if t.IPv6 == nil {
				return nil, common.NewBasicError(ErrBindWithoutPubV6, nil, "addr", s, "ip", bind.Addr)
			}
			if t.IPv6.bind != nil {
				return nil, common.NewBasicError(ErrTooManyBindV6, nil, "addr", s)
			}
			t.IPv6.bind = &addr.AppAddr{L3: addr.HostIPv6(ip), L4: t.IPv6.overlay.L4()}
		}
	}
	if desc := t.validate(); len(desc) > 0 {
		return nil, common.NewBasicError(desc, nil, "addr", s, "overlay", ot)
	}
	return t, nil
}

func (b RawBRIntAddr) String() string {
	var s []string
	s = append(s, fmt.Sprintf("PublicOverlay: %s", b.PublicOverlay))
	if len(b.BindOverlay) > 0 {
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

// Convert a RawBRIntf struct (filled from JSON) to a TopoAddr (used by Go code)
func (b RawBRIntf) localTopoAddr(o overlay.Type) (*TopoAddr, error) {
	rbram := make(RawBRAddrMap)
	rbram[o.ToIP().String()] = &RawOverlayBind{
		PublicOverlay: b.PublicOverlay,
		BindOverlay:   b.BindOverlay,
	}
	return rbram.ToTopoAddr(o)
}

// make an OverlayAddr object from a BR interface Remote entry
func (b RawBRIntf) remoteAddr(o overlay.Type) (*overlay.OverlayAddr, error) {
	ip := net.ParseIP(b.RemoteOverlay.Addr)
	if ip == nil {
		return nil, common.NewBasicError("Could not parse remote IP from string", nil,
			"ip", b.RemoteOverlay.Addr)
	}
	if o.IsUDP() == (b.RemoteOverlay.OverlayPort == 0) {
		return nil, common.NewBasicError(ErrOverlayPort, nil, "addr", b.RemoteOverlay)
	}
	l4 := addr.NewL4UDPInfo(uint16(b.RemoteOverlay.OverlayPort))
	return overlay.NewOverlayAddr(addr.HostFromIP(ip), l4)
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

type RawAddr struct {
	Addr string
}

func (a RawAddr) String() string {
	return fmt.Sprintf("%s", a.Addr)
}

type RawAddrPort struct {
	Addr   string
	L4Port int
}

func (a RawAddrPort) String() string {
	return fmt.Sprintf("%s:%d", a.Addr, a.L4Port)
}

type RawAddrOverlay struct {
	Addr        string
	OverlayPort int `json:",omitempty"`
}

func (a RawAddrOverlay) String() string {
	return fmt.Sprintf("%s:%d", a.Addr, a.OverlayPort)
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
