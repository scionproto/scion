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
	t := &TopoAddr{Overlay: ot}
	if err := t.fromRAI(s); err != nil {
		return nil, err
	}
	if desc := t.validate(); len(desc) > 0 {
		return nil, common.NewBasicError(desc, nil, "addr", s, "overlay", ot)
	}
	return t, nil
}

func (t *TopoAddr) fromRAI(s *RawAddrInfo) error {
	// Public addresses
	for _, pub := range s.Public {
		ip := net.ParseIP(pub.Addr)
		if ip == nil {
			return common.NewBasicError(ErrInvalidPub, nil, "addr", s, "ip", pub.Addr)
		}
		oPort := uint16(pub.OverlayPort)
		if oPort == 0 {
			oPort = overlay.EndhostPort
		} else if !t.Overlay.IsUDP() {
			return common.NewBasicError(ErrOverlayPort, nil, "addr", s)
		}
		l4 := addr.NewL4UDPInfo(uint16(pub.L4Port))
		var ol4 addr.L4Info
		if t.Overlay.IsUDP() {
			ol4 = addr.NewL4UDPInfo(oPort)
		}
		if ip.To4() != nil {
			if t.IPv4 != nil {
				return common.NewBasicError(ErrTooManyPubV4, nil, "addr", s)
			}
			l3 := addr.HostIPv4(ip)
			t.IPv4 = &pubBindAddr{}
			t.IPv4.pub = &addr.AppAddr{L3: l3, L4: l4}
			t.IPv4.overlay, _ = overlay.NewOverlayAddr(l3, ol4)
		} else {
			if t.IPv6 != nil {
				return common.NewBasicError(ErrTooManyPubV6, nil, "addr", s)
			}
			l3 := addr.HostIPv6(ip)
			t.IPv6 = &pubBindAddr{}
			t.IPv6.pub = &addr.AppAddr{L3: l3, L4: l4}
			t.IPv6.overlay, _ = overlay.NewOverlayAddr(l3, ol4)
		}
	}
	// Bind Addresses
	for _, bind := range s.Bind {
		ip := net.ParseIP(bind.Addr)
		if ip == nil {
			return common.NewBasicError(ErrInvalidBind, nil, "addr", s, "ip", bind.Addr)
		}
		l4 := addr.NewL4UDPInfo(uint16(bind.L4Port))
		if ip.To4() != nil {
			if t.IPv4 == nil {
				return common.NewBasicError(ErrBindWithoutPubV4, nil, "addr", s, "ip", bind.Addr)
			}
			if t.IPv4.bind != nil {
				return common.NewBasicError(ErrTooManyBindV4, nil, "addr", s)
			}
			t.IPv4.bind = &addr.AppAddr{L3: addr.HostIPv4(ip), L4: l4}
		} else {
			if t.IPv6 == nil {
				return common.NewBasicError(ErrBindWithoutPubV6, nil, "addr", s, "ip", bind.Addr)
			}
			if t.IPv6.bind != nil {
				return common.NewBasicError(ErrTooManyBindV6, nil, "addr", s)
			}
			t.IPv6.bind = &addr.AppAddr{L3: addr.HostIPv6(ip), L4: l4}
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
	return ""
}

func (t *TopoAddr) PublicAddr(ot overlay.Type) *addr.AppAddr {
	return t.getAddr(ot).PublicAddr()
}

func (t *TopoAddr) BindAddr(ot overlay.Type) *addr.AppAddr {
	return t.getAddr(ot).BindAddr()
}

func (t *TopoAddr) OverlayAddr(ot overlay.Type) *overlay.OverlayAddr {
	return t.getAddr(ot).OverlayAddr()
}

func (t *TopoAddr) BindOrPublic(ot overlay.Type) *addr.AppAddr {
	return t.getAddr(ot).BindOrPublic()
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

func (t *TopoAddr) Equal(o *TopoAddr) bool {
	if t.Overlay != o.Overlay {
		return false
	}
	if !t.IPv4.equal(o.IPv4) {
		return false
	}
	if !t.IPv6.equal(o.IPv6) {
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

type pubBindAddr struct {
	pub     *addr.AppAddr
	bind    *addr.AppAddr
	overlay *overlay.OverlayAddr
}

func (t *pubBindAddr) PublicAddr() *addr.AppAddr {
	return t.pub
}

func (t *pubBindAddr) BindAddr() *addr.AppAddr {
	return t.bind
}

func (t *pubBindAddr) OverlayAddr() *overlay.OverlayAddr {
	return t.overlay
}

func (t *pubBindAddr) BindOrPublic() *addr.AppAddr {
	if t.bind == nil {
		return t.pub
	}
	return t.bind
}

func (t1 *pubBindAddr) equal(t2 *pubBindAddr) bool {
	if (t1 == nil) && (t2 == nil) {
		return true
	}
	if (t1 == nil) != (t2 == nil) {
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
	return fmt.Sprintf("public: %v bind: %v overlay: %v", a.pub, a.bind, a.overlay)
}
