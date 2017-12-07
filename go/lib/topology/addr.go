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
	"strings"

	//log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
)

const (
	ErrInvalidPub       = "Invalid public IP address in topology"
	ErrInvalidBind      = "Invalid bind IP address in topology"
	ErrTooManyPubV4     = "Too many public IPv4 addresses"
	ErrTooManyPubV6     = "Too many public IPv6 addresses"
	ErrTooManyBindV4    = "Too many bind IPv4 addresses"
	ErrTooManyBindV6    = "Too many bind IPv6 addresses"
	ErrBindWithoutPubV4 = "Bind IPv4 address without any public IPv4 address"
	ErrBindWithoutPubV6 = "Bind IPv6 address without any public IPv6 address"
	ErrExactlyOnePub    = "Overlay requires exactly one public address"
	ErrAtLeastOnePub    = "Overlay requires at least one public address"
	ErrOverlayPort      = "Overlay port set for non-UDP overlay"
)

type TopoAddr struct {
	IPv4    *topoAddrInt
	IPv6    *topoAddrInt
	Overlay overlay.Type
}

// Create TopoAddr from RawAddrInfo, depending on supplied Overlay type
func TopoAddrFromRAI(s *RawAddrInfo, ot overlay.Type) (*TopoAddr, error) {
	switch ot {
	case overlay.IPv4, overlay.IPv6, overlay.IPv46, overlay.UDPIPv4,
		overlay.UDPIPv6, overlay.UDPIPv46:
	default:
		return nil, common.NewCError("Unsupported overlay type", "type", ot)
	}
	t := &TopoAddr{Overlay: ot}
	if err := t.FromRAI(s); err != nil {
		return nil, err
	}
	if t.IPv4 != nil && ot.IsUDP() && t.IPv4.OverlayPort == 0 {
		t.IPv4.OverlayPort = overlay.EndhostPort
	}
	if t.IPv6 != nil && ot.IsUDP() && t.IPv6.OverlayPort == 0 {
		t.IPv6.OverlayPort = overlay.EndhostPort
	}
	if desc := t.validate(); len(desc) > 0 {
		return nil, common.NewCError(desc, "addr", s, "overlay", t.Overlay)
	}
	return t, nil
}

func (t *TopoAddr) FromRAI(s *RawAddrInfo) error {
	// Public addresses
	for _, pub := range s.Public {
		ip := net.ParseIP(pub.Addr)
		if ip == nil {
			return common.NewCError(ErrInvalidPub, "addr", s, "ip", pub.Addr)
		}
		if ip.To4() != nil {
			if t.IPv4 != nil {
				return common.NewCError(ErrTooManyPubV4, "addr", s)
			}
			t.IPv4 = &topoAddrInt{pubIP: ip, pubL4Port: pub.L4Port, OverlayPort: pub.OverlayPort}
		} else {
			if t.IPv6 != nil {
				return common.NewCError(ErrTooManyPubV6, "addr", s)
			}
			t.IPv6 = &topoAddrInt{pubIP: ip, pubL4Port: pub.L4Port, OverlayPort: pub.OverlayPort}
		}
	}
	// Bind Addresses
	for _, bind := range s.Bind {
		ip := net.ParseIP(bind.Addr)
		if ip == nil {
			return common.NewCError(ErrInvalidBind, "addr", s, "ip", bind.Addr)
		}
		if ip.To4() != nil {
			if t.IPv4 == nil {
				return common.NewCError(ErrBindWithoutPubV4, "addr", s, "ip", bind.Addr)
			}
			if t.IPv4.bindIP != nil {
				return common.NewCError(ErrTooManyBindV4, "addr", s)
			}
			t.IPv4.bindIP = ip
			t.IPv4.bindL4Port = bind.L4Port
		} else {
			if t.IPv6 == nil {
				return common.NewCError(ErrBindWithoutPubV6, "addr", s, "ip", bind.Addr)
			}
			if t.IPv6.bindIP != nil {
				return common.NewCError(ErrTooManyBindV6, "addr", s)
			}
			t.IPv6.bindIP = ip
			t.IPv6.bindL4Port = bind.L4Port
		}
	}
	return nil
}

func (t *TopoAddr) validate() string {
	if t.Overlay.IsIPv4() != t.Overlay.IsIPv6() {
		// Single-stack overlay
		if (t.IPv4 == nil) == (t.IPv6 == nil) {
			// Either both addresses are present, or both are empty.
			return ErrExactlyOnePub
		}
	} else {
		// Dual-stack overlay
		if t.IPv4 == nil && t.IPv6 == nil {
			return ErrAtLeastOnePub
		}
	}
	if !t.Overlay.IsUDP() {
		if (t.IPv4 != nil && t.IPv4.OverlayPort != 0) ||
			(t.IPv6 != nil && t.IPv6.OverlayPort != 0) {
			return ErrOverlayPort
		}
	}
	return ""
}

// Extract the relevant (v4 or v6) L4Port from a TopoAddr
func (t *TopoAddr) PubL4PortFromAddr(a addr.HostAddr) (int, bool, error) {
	switch a.Type() {
	case addr.HostTypeIPv4:
		if t.IPv4 == nil {
			return 0, false, common.NewCError("HostAddr is v4, but Topoaddr does not have v4 address",
				"topoaddr", t, "hostaddr", a)
		}
		if !t.Overlay.IsIPv4() {
			return 0, false, common.NewCError("HostAddr is v4, but TopoAddr has non-v4 overlay",
				"topoaddr", t, "hostaddr", a)
		}
		return t.IPv4.pubL4Port, t.IPv4.pubIP.Equal(a.IP()), nil
	case addr.HostTypeIPv6:
		if t.IPv6 == nil {
			return 0, false, common.NewCError("HostAddr is v6, but Topoaddr does not have v6 address",
				"topoaddr", t, "hostaddr", a)
		}
		if !t.Overlay.IsIPv6() {
			return 0, false, common.NewCError("HostAddr is v6, but TopoAddr has non-v6 overlay",
				"topoaddr", t, "hostaddr", a)
		}
		return t.IPv6.pubL4Port, t.IPv6.pubIP.Equal(a.IP()), nil
	default:
		return 0, false, common.NewCError("Unknown HostAddr type", "type", a)
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
		ai.OverlayPort = ti.OverlayPort
	}
	return ai
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

func (t *TopoAddr) String() string {
	var s []string
	s = append(s, "TopoAddr{")
	if t.IPv4 != nil {
		s = append(s, fmt.Sprintf("IPv4:{%s},", t.IPv4))
	}
	if t.IPv6 != nil {
		s = append(s, fmt.Sprintf("IPv6:{%s},", t.IPv6))
	}
	s = append(s, fmt.Sprintf("Overlay: %s}", t.Overlay))
	return strings.Join(s, "")
}

type AddrInfo struct {
	Overlay     overlay.Type
	IP          net.IP
	L4Port      int
	OverlayPort int
}

func (a *AddrInfo) Key() string {
	return fmt.Sprintf("%s:%d", a.IP, a.L4Port)
}

func (a *AddrInfo) Reset() {
	a.Overlay = overlay.Invalid
	a.IP = a.IP[:0]
	a.L4Port = 0
	a.OverlayPort = 0
}

func (a *AddrInfo) String() string {
	// using %+v here would cause infinite recursion
	return fmt.Sprintf("Addrinfo{Overlay: %s, IP: %s, L4Port: %d, OverlayPort: %d}",
		a.Overlay, a.IP, a.L4Port, a.OverlayPort)
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

func (til *topoAddrInt) String() string {
	return fmt.Sprintf("public: [%s]:%d bind: [%s]:%d overlayPort: %d",
		til.pubIP, til.pubL4Port, til.bindIP, til.bindL4Port, til.OverlayPort)
}
