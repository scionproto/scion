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
	"fmt"
	"net"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay"
)

type TopoAddr struct {
	IPv4    *topoAddrInt
	IPv6    *topoAddrInt
	Overlay overlay.Type
}

// Create TopoAddr from RawAddrInfo, depending on desired Overlay type
func (s *RawAddrInfo) ToTopoAddr(ot overlay.Type) (t *TopoAddr, err *common.Error) {
	switch ot {
	case overlay.IPv4:
		t, err = topoAddrFromIPv4(s, false)
	case overlay.IPv6:
		t, err = topoAddrFromIPv6(s, false)
	case overlay.IPv46:
		t, err = topoAddrFromIPv46(s, false)
	case overlay.UDPIPv4:
		t, err = topoAddrFromIPv4(s, true)
	case overlay.UDPIPv6:
		t, err = topoAddrFromIPv6(s, true)
	case overlay.UDPIPv46:
		t, err = topoAddrFromIPv46(s, true)
	default:
		err = common.NewError("Unsupported overlay type", "type", ot)
	}
	if err != nil {
		return
	}
	t.Overlay = ot
	return
}

// Convert a RawBRIntf struct (filled from JSON) to a TopoAddr (used by Go code)
func localTopoAddrFromBrInt(b RawBRIntf, o overlay.Type) (*TopoAddr, *common.Error) {
	s := &RawAddrInfo{
		Public: []RawAddrPortOverlay{
			{RawAddrPort: RawAddrPort{Addr: b.Public.Addr, L4Port: b.Public.L4Port}},
		},
	}
	if b.Bind != nil {
		s.Bind = []RawAddrPort{{Addr: b.Bind.Addr, L4Port: b.Bind.L4Port}}
	}
	return s.ToTopoAddr(o)
}

// make an AddrInfo object from a BR interface Remote entry
func remoteAddrInfoFromBrInt(b RawBRIntf, o overlay.Type) (*AddrInfo, *common.Error) {
	ip := net.ParseIP(b.Remote.Addr)
	if ip == nil {
		return nil, common.NewError("Could not parse remote IP from string", "ip", b.Remote.Addr)
	}
	return &AddrInfo{Overlay: o, IP: ip, L4Port: b.Remote.L4Port}, nil
}

// TopoAddr from RawAddrInfo for IPv4 addresses
func topoAddrFromIPv4(s *RawAddrInfo, udp bool) (*TopoAddr, *common.Error) {
	t := &TopoAddr{}
	t.IPv4 = &topoAddrInt{}
	if len(s.Public) != 1 {
		return t, common.NewError(
			fmt.Sprintf("Topology with %s overlay must have exactly one public address",
				overlay.IPv4),
			"addr", s)
	}
	pub := s.Public[0]
	t.IPv4.pubIP = net.ParseIP(pub.Addr)
	if t.IPv4.pubIP == nil || t.IPv4.pubIP.To4() == nil {
		return nil, common.NewError("Invalid public IPv4 address in topology", "addr", s)
	}
	t.IPv4.OverlayPort = pub.OverlayPort
	if !udp && t.IPv4.OverlayPort != 0 {
		return nil, common.NewError("Overlay port set for non-UDP overlay", "addr", s)
	}
	t.IPv4.pubL4Port = pub.L4Port
	if len(s.Bind) > 1 {
		return t, common.NewError(
			fmt.Sprintf("Topology with %s overlay must have at most one bind address", overlay.IPv4),
			"addr", s)
	}
	if len(s.Bind) == 1 {
		bind := s.Bind[0]
		t.IPv4.bindIP = net.ParseIP(bind.Addr)
		if t.IPv4.bindIP == nil || t.IPv4.bindIP.To4() == nil {
			return nil, common.NewError("Invalid bind IPv4 address in topology", "addr", s)
		}
		t.IPv4.bindL4Port = bind.L4Port
	}
	return t, nil
}

// TODO(klausman) The three functions below (topoAddrFromIPv{4,6,46}) are very
// repetitive. Can parts be factored out?

// TopoAddr from RawAddrInfo for IPv6 addresses
func topoAddrFromIPv6(s *RawAddrInfo, udp bool) (*TopoAddr, *common.Error) {
	t := &TopoAddr{}
	t.IPv6 = &topoAddrInt{}
	if len(s.Public) != 1 {
		return t, common.NewError(
			fmt.Sprintf("Topology with %s overlay must have exactly one public address",
				overlay.IPv6),
			"addr", s)
	}
	pub := s.Public[0]
	t.IPv6.pubIP = net.ParseIP(pub.Addr)
	if t.IPv6.pubIP == nil || t.IPv6.pubIP.To4() != nil {
		return nil, common.NewError("Invalid public IPv6 address in topology", "addr", s)
	}
	t.IPv6.OverlayPort = pub.OverlayPort
	if !udp && t.IPv6.OverlayPort != 0 {
		return nil, common.NewError("Overlay port set for non-UDP overlay", "addr", s)
	}
	t.IPv6.pubL4Port = pub.L4Port
	if len(s.Bind) > 1 {
		return t, common.NewError(
			fmt.Sprintf("Topology with %s overlay must have at most one bind address", overlay.IPv6),
			"addr", s)
	}
	if len(s.Bind) == 1 {
		bind := s.Bind[0]
		t.IPv6.bindIP = net.ParseIP(bind.Addr)
		if t.IPv6.bindIP == nil || t.IPv6.bindIP.To4() != nil {
			return nil, common.NewError("Invalid bind IPv6 address in topology", "addr", bind.Addr)
		}
		t.IPv6.bindL4Port = bind.L4Port
	}
	return t, nil
}

// TopoAddr from RawAddrInfo for IPv4 and/or IPv6 addresses
func topoAddrFromIPv46(s *RawAddrInfo, udp bool) (*TopoAddr, *common.Error) {
	t := &TopoAddr{}
	if len(s.Public) == 0 {
		return t, common.NewError(
			fmt.Sprintf("Topology with %s overlay must have at least one public address",
				overlay.IPv46),
			"addr", s)
	}
	// Public addresses
	for _, pub := range s.Public {
		if !udp && pub.OverlayPort != 0 {
			return nil, common.NewError("Overlay port set for non-UDP overlay", "addr", s)
		}
		ip := net.ParseIP(pub.Addr)
		if ip == nil {
			return nil, common.NewError("Invalid public IP address in topology", "addr", s, "ip", pub.Addr)
		}
		if ip.To4() != nil {
			if t.IPv4 != nil {
				return t, common.NewError(
					fmt.Sprintf("Topology with %s overlay can not have more than one public IPv4 address",
						overlay.IPv46),
					"addr", s)
			}
			t.IPv4 = &topoAddrInt{pubIP: ip, pubL4Port: pub.L4Port, OverlayPort: pub.OverlayPort}
		} else {
			if t.IPv6 != nil {
				return t, common.NewError(
					fmt.Sprintf("Topology with %s overlay can not have more than one public IPv6 address",
						overlay.IPv46),
					"addr", s)
			}
			t.IPv6 = &topoAddrInt{pubIP: ip, pubL4Port: pub.L4Port, OverlayPort: pub.OverlayPort}
		}
	}
	// Bind Addresses
	for _, bind := range s.Bind {
		ip := net.ParseIP(bind.Addr)
		if ip == nil {
			return nil, common.NewError("Invalid bind IP address in topology", "addr", s, "ip", bind.Addr)
		}
		if ip.To4() != nil {
			if t.IPv4 == nil {
				return t, common.NewError("Topology with IPv4 bind address but no public IPv4 address")
			}
			if t.IPv4.bindIP != nil {
				return t, common.NewError(
					fmt.Sprintf("Topology with %s overlay can not have more than one IPv4 bind address",
						overlay.IPv46),
					"addr", s)
			}
			t.IPv4.bindIP = ip
			t.IPv4.bindL4Port = bind.L4Port
		} else {
			if t.IPv6 == nil {
				return t, common.NewError("Topology with IPv6 bind address but no public IPv6 address")
			}
			if t.IPv6.bindIP != nil {
				return t, common.NewError(
					fmt.Sprintf("Topology with %s overlay can not have more than one IPv6 bind address",
						overlay.IPv46),
					"addr", s)
			}
			t.IPv6.bindIP = ip
			t.IPv6.bindL4Port = bind.L4Port
		}
	}
	return t, nil
}

// Extract the relevant (v4 or v6) L4Port from a TopoAddr
func (t *TopoAddr) PubL4PortFromAddr(a addr.HostAddr) (int, bool, *common.Error) {
	switch a.Type() {
	case addr.HostTypeIPv4:
		if t.IPv4 == nil || !t.Overlay.IsIPv4() {
			return 0, false, common.NewError("IPv4 Hostaddr with empty IPv4 field")
		}
		return t.IPv4.pubL4Port, t.IPv4.pubIP.Equal(a.IP()), nil
	case addr.HostTypeIPv6:
		if t.IPv6 == nil || !t.Overlay.IsIPv6() {
			return 0, false, common.NewError("IPv6 Hostaddr with empty IPv6 field")
		}
		return t.IPv6.pubL4Port, t.IPv6.pubIP.Equal(a.IP()), nil
	default:
		// TODO(klausman): Log? Return error?
		log.Debug("Unknown type of a", "type", fmt.Sprintf("%T", a))
		return 0, false, common.NewError(fmt.Sprintf("Unknown HostAddr type: %T", a))

	}
}

func (t *TopoAddr) PublicAddrInfo(ot overlay.Type) *AddrInfo {
	return t.addrInfo(ot, true)
}

func (t *TopoAddr) BindAddrInfo(ot overlay.Type) *AddrInfo {
	return t.addrInfo(ot, false)
}

func (t *TopoAddr) addrInfo(ot overlay.Type, public bool) *AddrInfo {
	if t.IPv6 != nil && ot.IsIPv6() {
		return t.mkAddrInfo(t.IPv6, ot.To6(), public)
	}
	if t.IPv4 != nil && ot.IsIPv4() {
		return t.mkAddrInfo(t.IPv4, ot.To4(), public)
	}
	return nil
}

func (t *TopoAddr) mkAddrInfo(ti *topoAddrInt, ot overlay.Type, public bool) *AddrInfo {
	ai := &AddrInfo{Overlay: ot.ToIP(), IP: ti.bindIP, L4Port: ti.bindL4Port}
	if public || ai.IP == nil {
		ai.IP = ti.pubIP
		ai.L4Port = ti.pubL4Port
	}
	if ot.IsUDP() {
		ai.Overlay = ot
		if ti.OverlayPort != 0 {
			ai.OverlayPort = ti.OverlayPort
		} else {
			ai.OverlayPort = overlay.EndhostPort
		}
	}
	return ai
}

type AddrInfo struct {
	Overlay     overlay.Type
	IP          net.IP
	L4Port      int
	OverlayPort int
}

func (a *AddrInfo) String() string {
	// using %+v here would cause infinite recursion
	return fmt.Sprintf("Addrinfo{Overlay: %s, IP: %s, L4Port: %d, OverlayPort: %d}",
		a.Overlay, a.IP, a.L4Port, a.OverlayPort)
}

func (a *AddrInfo) Key() string {
	return fmt.Sprintf("%s:%d", a.IP, a.L4Port)
}

// Note: TopoAddrV4 and V6 *must* have their pubIP and pubL4Port members set to
// valid values for the structure to be valid at all. The remaining members are
// optional, but if either of bindIP or bindL4Port is set, the other Bind
// variable must also be set. OverlayPort is currently only valid for UDP
// overlays. Setting it for "native" topologies will result in an error.
type topoAddrInt struct {
	pubIP       net.IP
	pubL4Port   int
	bindIP      net.IP
	bindL4Port  int
	OverlayPort int
}

func (t topoAddrInt) PublicAddr() net.IP {
	return t.pubIP
}

func (t topoAddrInt) PublicL4Port() int {
	return t.pubL4Port
}

func (t topoAddrInt) BindAddr() net.IP {
	if len(t.bindIP) > 0 {
		return t.bindIP
	} else {
		return t.pubIP
	}
}

func (t topoAddrInt) BindL4Port() int {
	if len(t.bindIP) > 0 {
		return t.bindL4Port
	} else {
		return t.pubL4Port
	}
}

func (ti1 *topoAddrInt) equal(ti2 *topoAddrInt) bool {
	if ti1 == nil && ti2 == nil {
		return true
	}
	if ti1 == nil || ti2 == nil {
		return false
	}
	if ti1.pubL4Port != ti2.pubL4Port {
		return false
	}
	if ti1.bindL4Port != ti2.bindL4Port {
		return false
	}
	if ti1.OverlayPort != ti2.OverlayPort {
		return false
	}
	if !ti1.pubIP.Equal(ti2.pubIP) {
		return false
	}
	if !ti1.bindIP.Equal(ti2.bindIP) {
		return false
	}
	return true
}

func (t1 *TopoAddr) Equal(t2 *TopoAddr) bool {
	if t1.Overlay != t2.Overlay {
		return false
	}
	if !t1.IPv4.equal(t2.IPv4) {
		return false
	}
	if !t1.IPv6.equal(t2.IPv6) {
		return false
	}
	return true
}
