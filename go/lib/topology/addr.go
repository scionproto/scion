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
	IPv4    *pubBindAddr
	IPv6    *pubBindAddr
	Overlay overlay.Type
}

// Create TopoAddr from RawAddrInfo, depending on supplied Overlay type
func TopoAddrFromRAI(s *RawAddrInfo, ot overlay.Type) (*TopoAddr, error) {
	switch ot {
	case overlay.IPv4, overlay.IPv6, overlay.IPv46, overlay.UDPIPv4,
		overlay.UDPIPv6, overlay.UDPIPv46:
	default:
		return nil, common.NewBasicError("Unsupported overlay type", nil, "type", ot)
	}
	t := &TopoAddr{}
	if err := t.FromRAI(s, ot); err != nil {
		return nil, err
	}
	if desc := t.validate(); len(desc) > 0 {
		return nil, common.NewBasicError(desc, nil, "addr", s, "overlay", ot)
	}
	return t, nil
}

func (t *TopoAddr) FromRAI(s *RawAddrInfo, ot overlay.Type) error {
	t.Overlay = ot
	// Public addresses
	for _, pub := range s.Public {
		ip := net.ParseIP(pub.Addr)
		if ip == nil {
			return common.NewBasicError(ErrInvalidPub, nil, "addr", s, "ip", pub.Addr)
		}
		oport := uint16(pub.OverlayPort)
		if pub.OverlayPort == 0 {
			oport = overlay.EndhostPort
		}
		if ip.To4() != nil {
			if t.IPv4 != nil {
				return common.NewBasicError(ErrTooManyPubV4, nil, "addr", s)
			}
			t.IPv4 = &pubBindAddr{}
			t.IPv4.pub = addr.NewAppAddrUDPIPv4(ip, uint16(pub.L4Port))
			if ot.IsUDP() {
				t.IPv4.overlay = addr.NewOverlayAddrUDPIPv4(ip, oport)
			} else {
				if pub.OverlayPort != 0 {
					return common.NewBasicError(ErrOverlayPort, nil, "addr", s)
				}
				t.IPv4.overlay = addr.NewOverlayAddrIPv4(ip)
			}
		} else {
			if t.IPv6 != nil {
				return common.NewBasicError(ErrTooManyPubV6, nil, "addr", s)
			}
			t.IPv6 = &pubBindAddr{}
			t.IPv6.pub = addr.NewAppAddrUDPIPv6(ip, uint16(pub.L4Port))
			if ot.IsUDP() {
				t.IPv6.overlay = addr.NewOverlayAddrUDPIPv6(ip, oport)
			} else {
				if pub.OverlayPort != 0 {
					return common.NewBasicError(ErrOverlayPort, nil, "addr", s)
				}
				t.IPv6.overlay = addr.NewOverlayAddrIPv6(ip)
			}
		}
	}
	// Bind Addresses
	for _, bind := range s.Bind {
		ip := net.ParseIP(bind.Addr)
		if ip == nil {
			return common.NewBasicError(ErrInvalidBind, nil, "addr", s, "ip", bind.Addr)
		}
		if ip.To4() != nil {
			if t.IPv4 == nil {
				return common.NewBasicError(ErrBindWithoutPubV4, nil, "addr", s, "ip", bind.Addr)
			}
			if t.IPv4.bind != nil {
				return common.NewBasicError(ErrTooManyBindV4, nil, "addr", s)
			}
			t.IPv4.bind = addr.NewAppAddrUDPIPv4(ip, uint16(bind.L4Port))
		} else {
			if t.IPv6 == nil {
				return common.NewBasicError(ErrBindWithoutPubV6, nil, "addr", s, "ip", bind.Addr)
			}
			if t.IPv6.bind != nil {
				return common.NewBasicError(ErrTooManyBindV6, nil, "addr", s)
			}
			t.IPv6.bind = addr.NewAppAddrUDPIPv6(ip, uint16(bind.L4Port))
		}
	}
	// Use Public as Bind address if Bind was not specified
	// Check IPv4
	if t.IPv4 != nil && t.IPv4.bind == nil {
		t.IPv4.bind = t.IPv4.pub
	}
	// Check IPv6
	if t.IPv6 != nil && t.IPv6.bind == nil {
		t.IPv6.bind = t.IPv6.pub
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
	return ""
}

/* FIXME
func (t *TopoAddr) Type() overlay.Type {
	t1 := t.IPv4
	t2 := t.IPv6
	switch {
	case t1.isUDP() && t2.isUDP():
		return overlay.UDPIPv46
	case t1 != nil && t2 != nil:
		return overlay.IPv46
	case t1 != nil:
		return toOverlayType(t1)
	case t2 != nil:
		return toOverlayType(t2)
	}
	return overlay.Invalid
}

func toOverlayType(t addr.OverlayType) overlay.Type {
	switch t.(type) {
	case addr.OverlayTypeIPv4:
		return overlay.IPv4
	case addr.OverlayTypeIPv6:
		return overlay.IPv6
	case addr.OverlayTypeUDPIPv4:
		return overlay.UDPIPv4
	case addr.OverlayTypeUDPIPv6:
		return overlay.UDPIPv6
	}
	return overlay.Invalid
}

func isUDP(t addr.OverlayType) bool {
	switch t.(type) {
	case addr.OverlayTypeUDPIPv4:
		return true
	case addr.OverlayTypeUDPIPv6:
		return true
	}
	return false
}
*/

func (t *TopoAddr) PublicAddr(ot overlay.Type) addr.AppAddr {
	return t.getAddr(ot).PublicAddr()
}

func (t *TopoAddr) BindAddr(ot overlay.Type) addr.AppAddr {
	return t.getAddr(ot).BindAddr()
}

func (t *TopoAddr) OverlayAddr(ot overlay.Type) addr.OverlayAddr {
	return t.getAddr(ot).OverlayAddr()
}

func (t *TopoAddr) getAddr(ot overlay.Type) *pubBindAddr {
	if t.IPv6 != nil && ot.IsIPv6() {
		return t.IPv6
	}
	if t.IPv4 != nil && ot.IsIPv4() {
		return t.IPv4
	}
	return nil
}

func (t1 *TopoAddr) Equal(t2 *TopoAddr) bool {
	if (t1.IPv4 == nil) != (t2.IPv4 == nil) {
		return false
	}
	if (t1.IPv6 == nil) != (t2.IPv6 == nil) {
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
	return strings.Join(s, "")
}

// Note: TopoAddrV4 and V6 *must* have their pubIP and pubL4Port members set to
// valid values for the structure to be valid at all. The remaining members are
// optional, but if either of bindIP or bindL4Port is set, the other Bind
// variable must also be set. OverlayPort is currently only valid for UDP
// overlays. Setting it for "native" topologies will result in an error.
type pubBindAddr struct {
	pub     addr.AppAddr
	bind    addr.AppAddr
	overlay addr.OverlayAddr
}

func (t *pubBindAddr) PublicAddr() addr.AppAddr {
	return t.pub
}

func (t *pubBindAddr) BindAddr() addr.AppAddr {
	return t.bind
}

func (t *pubBindAddr) OverlayAddr() addr.OverlayAddr {
	return t.overlay
}

func (t1 *pubBindAddr) equal(t2 *pubBindAddr) bool {
	if (t1 == nil) && (t2 == nil) {
		return true
	}
	if (t1 == nil) != (t2 == nil) {
		return false
	}
	if (t1.pub == nil) != (t2.pub == nil) {
		return false
	}
	if (t1.bind == nil) != (t2.bind == nil) {
		return false
	}
	if (t1.overlay == nil) != (t2.overlay == nil) {
		return false
	}
	if !t1.pub.Eq(t2.pub) {
		return false
	}
	if !t1.bind.Eq(t2.bind) {
		return false
	}
	if !t1.overlay.Eq(t2.overlay) {
		return false
	}
	return true
}

func (a *pubBindAddr) String() string {
	return fmt.Sprintf("public: [%s]:%d bind: [%s]:%d overlay: [%s]:%d",
		a.pub.Addr(), a.pub.Port(), a.bind.Addr(), a.bind.Port(), a.overlay.Addr(), a.overlay.Port())
}
