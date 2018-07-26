// Copyright 2018 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by olicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package addr

import (
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/overlay"
)

// OverlayAddr
type OverlayType uint8

const (
	OverlayTypeNone OverlayType = iota
	OverlayTypeIPv4
	OverlayTypeIPv6
	OverlayTypeUDPIPv4
	OverlayTypeUDPIPv6
)

func (t OverlayType) ToOverlayType() overlay.Type {
	switch t {
	case OverlayTypeIPv4:
		return overlay.IPv4
	case OverlayTypeIPv6:
		return overlay.IPv6
	case OverlayTypeUDPIPv4:
		return overlay.UDPIPv4
	case OverlayTypeUDPIPv6:
		return overlay.UDPIPv6
	}
	return overlay.Invalid
}

func (t OverlayType) String() string {
	switch t {
	case OverlayTypeIPv4:
		return "IPv4"
	case OverlayTypeIPv6:
		return "IPv6"
	case OverlayTypeUDPIPv4:
		return "UDPIPv4"
	case OverlayTypeUDPIPv6:
		return "UDPIPv6"
	}
	return fmt.Sprintf("UNKNOWN (%d)", t)
}

type OverlayAddr interface {
	Copy() OverlayAddr
	Type() OverlayType
	Eq(OverlayAddr) bool
	Addr() HostAddr
	Port() uint16
	Network() string
	String() string
}

// OverlayAddr
func NewOverlayAddr(ip net.IP, port uint16) OverlayAddr {
	var overlay OverlayAddr
	if port != 0 {
		if ip.To4() != nil {
			overlay = NewOverlayAddrUDPIPv4(ip, port)
		} else if ip.To16() != nil {
			overlay = NewOverlayAddrUDPIPv6(ip, port)
		}
	} else {
		if ip.To4() != nil {
			overlay = NewOverlayAddrIPv4(ip)
		} else if ip.To16() != nil {
			overlay = NewOverlayAddrIPv6(ip)
		}
	}
	return overlay
}

func ToOverlayAddr(a net.Addr) OverlayAddr {
	switch v := a.(type) {
	case OverlayAddrIPv4:
		return v
	case OverlayAddrIPv6:
		return v
	case OverlayAddrUDPIPv4:
		return v
	case OverlayAddrUDPIPv6:
		return v
	}
	return nil
}

// OverlayAddrIPv4
type OverlayAddrIPv4 struct {
	addrPort
}

func NewOverlayAddrIPv4(ip net.IP) OverlayAddr {
	return OverlayAddrIPv4{addrPort{addr: HostIPv4(ip), port: 0}}
}

func (a OverlayAddrIPv4) Copy() OverlayAddr {
	return OverlayAddrIPv4{a.addrPort.cp()}
}

func (a OverlayAddrIPv4) Type() OverlayType {
	return OverlayTypeIPv4
}

func (a OverlayAddrIPv4) Eq(app OverlayAddr) bool {
	b, ok := app.(OverlayAddrIPv4)
	return ok && a.addrPort.eq(b.addrPort)
}

func (a OverlayAddrIPv4) Network() string {
	return "OverlayAddr"
}

func (a OverlayAddrIPv4) String() string {
	return fmt.Sprintf("%s", a.Addr())
}

// OverlayAddrIPv6
type OverlayAddrIPv6 struct {
	addrPort
}

func NewOverlayAddrIPv6(ip net.IP) OverlayAddr {
	return OverlayAddrIPv6{addrPort{addr: HostIPv6(ip), port: 0}}
}

func (a OverlayAddrIPv6) Copy() OverlayAddr {
	return OverlayAddrIPv6{a.addrPort.cp()}
}

func (a OverlayAddrIPv6) Type() OverlayType {
	return OverlayTypeIPv6
}

func (a OverlayAddrIPv6) Eq(app OverlayAddr) bool {
	b, ok := app.(OverlayAddrIPv6)
	return ok && a.addrPort.eq(b.addrPort)
}

func (a OverlayAddrIPv6) Network() string {
	return "OverlayAddr"
}

func (a OverlayAddrIPv6) String() string {
	return fmt.Sprintf("%s", a.Addr())
}

// OverlayAddrUDPIPv4
type OverlayAddrUDPIPv4 struct {
	addrPort
}

func NewOverlayAddrUDPIPv4(ip net.IP, port uint16) OverlayAddr {
	return OverlayAddrUDPIPv4{addrPort{addr: HostIPv4(ip), port: port}}
}

func (a OverlayAddrUDPIPv4) Copy() OverlayAddr {
	return OverlayAddrUDPIPv4{a.addrPort.cp()}
}

func (a OverlayAddrUDPIPv4) Type() OverlayType {
	return OverlayTypeUDPIPv4
}

func (a OverlayAddrUDPIPv4) Eq(app OverlayAddr) bool {
	b, ok := app.(OverlayAddrUDPIPv4)
	return ok && a.addrPort.eq(b.addrPort)
}

func (a OverlayAddrUDPIPv4) Network() string {
	return "OverlayAddr"
}

func (a OverlayAddrUDPIPv4) String() string {
	return fmt.Sprintf("%s:%d", a.Addr(), a.Port())
}

// OverlayAddrUDPIPv6
type OverlayAddrUDPIPv6 struct {
	addrPort
}

func NewOverlayAddrUDPIPv6(ip net.IP, port uint16) OverlayAddr {
	return OverlayAddrUDPIPv6{addrPort{addr: HostIPv6(ip), port: port}}
}

func (a OverlayAddrUDPIPv6) Copy() OverlayAddr {
	return OverlayAddrUDPIPv6{a.addrPort.cp()}
}

func (a OverlayAddrUDPIPv6) Type() OverlayType {
	return OverlayTypeUDPIPv6
}

func (a OverlayAddrUDPIPv6) Eq(app OverlayAddr) bool {
	b, ok := app.(OverlayAddrUDPIPv6)
	return ok && a.addrPort.eq(b.addrPort)
}

func (a OverlayAddrUDPIPv6) Network() string {
	return "OverlayAddr"
}

func (a OverlayAddrUDPIPv6) String() string {
	return fmt.Sprintf("%s:%d", a.Addr(), a.Port())
}
