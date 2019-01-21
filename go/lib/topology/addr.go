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
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
)

const (
	ErrUnsupportedOverlay   = "Unsupported overlay"
	ErrUnsupportedAddrType  = "Unsupported address type"
	ErrInvalidPub           = "Invalid public address"
	ErrInvalidBind          = "Invalid bind address"
	ErrAtLeastOnePub        = "Overlay requires at least one public address"
	ErrOverlayPort          = "Overlay port set for non-UDP overlay"
	ErrBindAddrEqPubAddr    = "Bind address equal to Public address"
	ErrMismatchOverlayAddr  = "Mismatch overlay type and address"
	ErrMismatchPubAddrType  = "Mismatch public address and type "
	ErrMismatchBindAddrType = "Mismatch bind address and type"
)

// TopoAddr wraps the possible addresses of a SCION service and describes
// the overlay to be used for contacting said service.
type TopoAddr struct {
	IPv4    *pubBindAddr
	IPv6    *pubBindAddr
	Overlay overlay.Type
}

// TestTopoAddr creates a new TopoAddr. This is only for testing and should
// never be used by apps.
func TestTopoAddr(v4AppAddr, v6AppAddr *addr.AppAddr,
	v4OverlayAddr, v6OverlayAddr *overlay.OverlayAddr) TopoAddr {

	return TopoAddr{
		IPv4: &pubBindAddr{
			pub:     v4AppAddr,
			overlay: v4OverlayAddr,
		},
		IPv6: &pubBindAddr{
			pub:     v6AppAddr,
			overlay: v6OverlayAddr,
		},
		Overlay: overlay.IPv46,
	}
}

// Create TopoAddr from RawAddrMap, depending on supplied Overlay type
func topoAddrFromRAM(s RawAddrMap, ot overlay.Type) (*TopoAddr, error) {
	if err := overlayCheck(ot); err != nil {
		return nil, err
	}
	t := &TopoAddr{Overlay: ot}
	if err := t.fromRaw(s); err != nil {
		return nil, common.NewBasicError("Failed to parse raw topo address", err, "addr", s)
	}
	return t, nil
}

func (t *TopoAddr) fromRaw(s RawAddrMap) error {
	for k, rpbo := range s {
		var hostType addr.HostAddrType
		pbo := &pubBindAddr{}
		switch k {
		case "IPv4":
			if !t.Overlay.IsIPv4() {
				return common.NewBasicError(ErrMismatchOverlayAddr, nil, "Overlay", t.Overlay)
			}
			t.IPv4 = pbo
			hostType = addr.HostTypeIPv4
		case "IPv6":
			if !t.Overlay.IsIPv6() {
				return common.NewBasicError(ErrMismatchOverlayAddr, nil, "Overlay", t.Overlay)
			}
			t.IPv6 = pbo
			hostType = addr.HostTypeIPv6
		default:
			return common.NewBasicError(ErrUnsupportedAddrType, nil, "Type", k)
		}
		if err := pbo.fromRaw(rpbo, t.Overlay.IsUDP()); err != nil {
			return err
		}
		// Check parsed addresses match the expected address type
		if pbo.pub.L3.Type() != hostType {
			return common.NewBasicError(ErrMismatchPubAddrType, nil,
				"AddrType", hostType, "Addr", pbo.pub)
		}
		if pbo.bind != nil {
			if pbo.bind.L3.Type() != hostType {
				return common.NewBasicError(ErrMismatchBindAddrType, nil,
					"AddrType", hostType, "Addr", pbo.bind)
			}
			// Check pub and bind are not the same address
			if pbo.pub.Equal(pbo.bind) {
				return common.NewBasicError(ErrBindAddrEqPubAddr, nil,
					"bindAddr", pbo.bind, "pubAddr", pbo.pub)
			}
		}
	}
	if t.IPv4 == nil && t.IPv6 == nil {
		// Both are empty.
		return common.NewBasicError(ErrAtLeastOnePub, nil)
	}
	return nil
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
	if t == nil || o == nil {
		return t == o
	}
	if t.Overlay != o.Overlay {
		return false
	}
	if !t.IPv4.Equal(o.IPv4) {
		return false
	}
	if !t.IPv6.Equal(o.IPv6) {
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

func (pbo *pubBindAddr) fromRaw(rpbo *RawPubBindOverlay, udpOverlay bool) error {
	var err error
	l3 := addr.HostFromIPStr(rpbo.Public.Addr)
	if l3 == nil {
		return common.NewBasicError(ErrInvalidPub, nil, "ip", rpbo.Public.Addr)
	}
	pbo.pub = &addr.AppAddr{
		L3: l3,
		L4: addr.NewL4UDPInfo(uint16(rpbo.Public.L4Port)),
	}
	pbo.overlay, err = newOverlayAddr(udpOverlay, pbo.pub.L3, rpbo.Public.OverlayPort)
	if err != nil {
		return err
	}
	if rpbo.Bind != nil {
		l3 := addr.HostFromIPStr(rpbo.Bind.Addr)
		if l3 == nil {
			return common.NewBasicError(ErrInvalidBind, nil, "ip", rpbo.Bind.Addr)
		}
		pbo.bind = &addr.AppAddr{
			L3: l3,
			L4: addr.NewL4UDPInfo(uint16(rpbo.Bind.L4Port)),
		}
	}
	return nil
}

func (t *pubBindAddr) PublicAddr() *addr.AppAddr {
	if t == nil {
		return nil
	}
	return t.pub
}

func (t *pubBindAddr) BindAddr() *addr.AppAddr {
	if t == nil {
		return nil
	}
	return t.bind
}

func (t *pubBindAddr) OverlayAddr() *overlay.OverlayAddr {
	if t == nil {
		return nil
	}
	return t.overlay
}

func (t *pubBindAddr) BindOrPublic() *addr.AppAddr {
	if t.bind == nil {
		return t.pub
	}
	return t.bind
}

func (t1 *pubBindAddr) Equal(t2 *pubBindAddr) bool {
	if (t1 == nil) && (t2 == nil) {
		return true
	}
	if (t1 == nil) != (t2 == nil) {
		return false
	}
	if !t1.pub.Equal(t2.pub) {
		return false
	}
	if !t1.bind.Equal(t2.bind) {
		return false
	}
	if !t1.overlay.Equal(t2.overlay) {
		return false
	}
	return true
}

func (a *pubBindAddr) String() string {
	return fmt.Sprintf("public: %v bind: %v overlay: %v", a.pub, a.bind, a.overlay)
}

func newOverlayAddr(udpOverlay bool, l3 addr.HostAddr, port int) (*overlay.OverlayAddr, error) {
	var ol4 addr.L4Info
	if !udpOverlay && port != 0 {
		return nil, common.NewBasicError(ErrOverlayPort, nil)
	} else if udpOverlay {
		if port == 0 {
			port = overlay.EndhostPort
		}
		ol4 = addr.NewL4UDPInfo(uint16(port))
	}
	return overlay.NewOverlayAddr(l3, ol4)
}

func overlayCheck(ot overlay.Type) error {
	switch ot {
	case overlay.IPv4, overlay.IPv6, overlay.IPv46, overlay.UDPIPv4,
		overlay.UDPIPv6, overlay.UDPIPv46:
	default:
		return common.NewBasicError(ErrUnsupportedOverlay, nil, "type", ot)
	}
	return nil
}
