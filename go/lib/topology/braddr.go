// Copyright 2018 ETH Zurich
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

type TopoBRAddr struct {
	IPv4    *OverBindAddr
	IPv6    *OverBindAddr
	Overlay overlay.Type
}

// Create TopoAddr from RawAddrMap, depending on supplied Overlay type
func topoBRAddrFromRBRAM(s RawBRAddrMap, ot overlay.Type) (*TopoBRAddr, error) {
	if err := overlayCheck(ot); err != nil {
		return nil, err
	}
	t := &TopoBRAddr{Overlay: ot}
	if err := t.fromRaw(s); err != nil {
		return nil, common.NewBasicError("Failed to parse raw topo address", err, "addr", s)
	}
	return t, nil
}

func (t *TopoBRAddr) fromRaw(s RawBRAddrMap) error {
	for k, rob := range s {
		var hostType addr.HostAddrType
		ob := &OverBindAddr{}
		switch k {
		case "IPv4":
			if !t.Overlay.IsIPv4() {
				return common.NewBasicError(ErrMismatchOverlayAddr, nil, "Overlay", t.Overlay)
			}
			t.IPv4 = ob
			hostType = addr.HostTypeIPv4
		case "IPv6":
			if !t.Overlay.IsIPv6() {
				return common.NewBasicError(ErrMismatchOverlayAddr, nil, "Overlay", t.Overlay)
			}
			t.IPv6 = ob
			hostType = addr.HostTypeIPv6
		default:
			return common.NewBasicError(ErrUnsupportedAddrType, nil, "Type", k)
		}
		if err := ob.fromRaw(rob, t.Overlay.IsUDP()); err != nil {
			return err
		}
		// Check parsed addresses match the expected address type
		if ob.PublicOverlay.L3().Type() != hostType {
			return common.NewBasicError(ErrMismatchPubAddrType, nil,
				"AddrType", hostType, "Addr", ob.PublicOverlay)
		}
		if ob.BindOverlay != nil {
			if ob.BindOverlay.L3().Type() != hostType {
				return common.NewBasicError(ErrMismatchBindAddrType, nil,
					"AddrType", hostType, "Addr", ob.BindOverlay)
			}
			// Check PublicOverlay and BindOverlay are not the same address
			if ob.PublicOverlay.Equal(ob.BindOverlay) {
				return common.NewBasicError(ErrBindAddrEqPubAddr, nil,
					"BindOverlayAddr", ob.BindOverlay, "PublicOverlayAddr", ob.PublicOverlay)
			}
		}
	}
	if t.IPv4 == nil && t.IPv6 == nil {
		// Both are empty.
		return common.NewBasicError(ErrAtLeastOnePub, nil)
	}
	return nil
}

func (t *TopoBRAddr) PublicOverlay(ot overlay.Type) *overlay.OverlayAddr {
	if oba := t.getAddr(ot); oba != nil {
		return oba.PublicOverlay
	}
	return nil
}

func (t *TopoBRAddr) BindOverlay(ot overlay.Type) *overlay.OverlayAddr {
	if oba := t.getAddr(ot); oba != nil {
		return oba.BindOverlay
	}
	return nil
}

func (t *TopoBRAddr) BindOrPublicOverlay(ot overlay.Type) *overlay.OverlayAddr {
	if oba := t.getAddr(ot); oba != nil {
		return oba.BindOrPublicOverlay()
	}
	return nil
}

func (t *TopoBRAddr) getAddr(ot overlay.Type) *OverBindAddr {
	if t == nil {
		return nil
	}
	if t.IPv6 != nil && ot.IsIPv6() {
		return t.IPv6
	}
	if t.IPv4 != nil && ot.IsIPv4() {
		return t.IPv4
	}
	return nil
}

func (t *TopoBRAddr) Equal(o *TopoBRAddr) bool {
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

func (t *TopoBRAddr) String() string {
	var s []string
	s = append(s, "TopoBRAddr{")
	if t.IPv4 != nil {
		s = append(s, fmt.Sprintf("IPv4:{%s},", t.IPv4))
	}
	if t.IPv6 != nil {
		s = append(s, fmt.Sprintf("IPv6:{%s},", t.IPv6))
	}
	s = append(s, fmt.Sprintf("Overlay: %s}", t.Overlay))
	return strings.Join(s, "")
}

type OverBindAddr struct {
	PublicOverlay *overlay.OverlayAddr
	BindOverlay   *overlay.OverlayAddr
}

func (ob *OverBindAddr) fromRaw(rob *RawOverlayBind, udpOverlay bool) error {
	l3 := addr.HostFromIPStr(rob.PublicOverlay.Addr)
	if l3 == nil {
		return common.NewBasicError(ErrInvalidPub, nil, "ip", rob.PublicOverlay.Addr)
	}
	ob.PublicOverlay = overlay.NewOverlayAddr(l3.IP(), uint16(rob.PublicOverlay.OverlayPort))
	if rob.BindOverlay != nil {
		l3 := addr.HostFromIPStr(rob.BindOverlay.Addr)
		if l3 == nil {
			return common.NewBasicError(ErrInvalidBind, nil, "ip", rob.BindOverlay.Addr)
		}
		ob.BindOverlay = overlay.NewOverlayAddr(l3.IP(), uint16(rob.PublicOverlay.OverlayPort))
	}
	return nil
}

func (t *OverBindAddr) BindOrPublicOverlay() *overlay.OverlayAddr {
	if t.BindOverlay != nil {
		return t.BindOverlay
	}
	return t.PublicOverlay
}

func (t1 *OverBindAddr) Equal(t2 *OverBindAddr) bool {
	if (t1 == nil) && (t2 == nil) {
		return true
	}
	if (t1 == nil) != (t2 == nil) {
		return false
	}
	if !t1.PublicOverlay.Equal(t2.PublicOverlay) {
		return false
	}
	if !t1.BindOverlay.Equal(t2.BindOverlay) {
		return false
	}
	return true
}

func (a *OverBindAddr) String() string {
	return fmt.Sprintf("PublicOverlay: %v BindOverlay: %v", a.PublicOverlay, a.BindOverlay)
}
