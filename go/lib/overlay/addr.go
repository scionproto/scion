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

package overlay

/*
// baseOverlayAddr
type baseOverlayAddr addr.AddrPort

func (a baseOverlayAddr) Copy() OverlayType {
	return baseOverlayAddr{addr: a.addr.Copy(), port: a.port}
}

func (a baseOverlayAddr) AddrPort() addr.AddrPort {
	return a.AddrPort
}

// OverlayAddrIPv4
type OverlayAddrIPv4 struct {
	baseOverlayAddr
}

func NewOverlayAddrIPv4(addr OverlayAddr) OverlayAddr {
	return OverlayAddrIPv4{addr: HostAddrIPv4{a.addr}, port: 0}
}

func (a OverlayAddrIPv4) Type() OverlayType {
	return OverlayAddrIPv4
}

// OverlayAddrIPv6
type OverlayAddrIPv6 struct {
	baseOverlayAddr
}

func NewOverlayAddrIPv6(addr OverlayAddr) OverlayAddr {
	return OverlayAddrIPv6{addr: HostAddrIPv6{addr}, port: 0}
}

func (a OverlayAddrIPv6) Type() OverlayType {
	return OverlayAddrIPv6
}

// OverlayAddrUDPIPv4
type OverlayAddrUDPIPv4 struct {
	baseOverlayAddr
}

func NewOverlayAddrUDPIPv4(addr OverlayAddr, port uint16) OverlayAddr {
	return OverlayAddrUDPIPv4{addr: HostAddrUDPIPv4{addr}, port: port}
}

func (a OverlayAddrUDPIPv4) Type() OverlayType {
	return OverlayAddrUDPIPv4
}

// OverlayAddrUDPIPv6
type OverlayAddrUDPIPv6 struct {
	baseOverlayAddr
}

func NewOverlayAddrUDPIPv6(addr OverlayAddr, port uint16) OverlayAddr {
	return OverlayAddrUDPIPv6{addr: HostAddrUDPIPv6{addr}, port: port}
}

func (a OverlayAddrUDPIPv6) Type() OverlayType {
	return OverlayAddrUDPIPv6
}
*/
/*
type OverlayAddr interface {
	Copy() OverlayAddr
	Eq(OverlayAddr) bool
	AddrPort() AddrPort
}

// Overlay IP type
// *****************************************
var _ OverlayAddr = (OverlayIP)(nil)

type OverlayIP net.IP

func NewOverlay(t Type, ip net.Ip, port uint16) OverlayAddr {
	switch t {
	case IPv4:
		if ip.To4() != nil {
			return OverlayIP{ip}
		}
	case IPv6:
		if ip.To4() == nil {
			return OverlayIP{ip}
		}
	case UDPIPv4:
		return OverlayUDP{addr: addr.HostAddrIPv4{ip}, port: port}
	case UDPIPv6:
		return OverlayUDP{addr: addr.HostAddrIPv6{ip}, port: port}
	}
	return nil
}

func (h OverlayIP) Copy() OverlayAddr {
	return OverlayIP(append(net.IP(nil), h...))
}

func (h OverlayIP) Eq(a OverlayAddr) bool {
	ha, ok := a.(OverlayIP)
	return ok && net.IP(h).Equal(net.IP(ha))
}

func (h OverlayIP) IP() net.IP {
	return net.IP(h)
}

func (h OverlayIP) Port() uint16 {
	return 0
}

func (h OverlayIP) Type() Type {
	if net.IP(h).To4() == nil {
		return IPv6
	}
	return IPv4
}

// Overlay UDP type
// *****************************************
var _ OverlayAddr = (OverlayUDP)(nil)

type OverlayUDP AddrPort

type OverlayUDP struct {
	addr addr.HostAddr
	port uint16
}
func (h OverlayUDP) Copy() OverlayAddr {
	c := OverlayUDP{port: h.port}
	c.addr = h.addr.Copy()
	return c
}

func (h OverlayUDP) Eq(a OverlayAddr) bool {
	ha, ok := a.(OverlayUDP)
	return ok && h.port == a.port && h.addr.Eq(a.addr)
}

func (h OverlayUDP) IP() net.IP {
	return h.addr.IP()
}

func (h OverlayUDP) Port() uint16 {
	return h.port
}

func (h OverlayUDP) Type() Type {
	if net.IP(h).To4() == nil {
		return UDPIPv6
	}
	return UDPIPv4
}

// Overlay IPv4 type
// *****************************************
var _ OverlayAddr = (OverlayIPv4)(nil)

type OverlayIPv4 net.IP

func (h OverlayIPv4) Copy() OverlayAddr {
	return OverlayIPv4(append(net.IP(nil), h...))
}

func (h OverlayIPv4) Eq(a OverlayAddr) bool {
	ha, ok := a.(OverlayIPv4)
	return ok && net.IP(h).Equal(net.IP(ha))
}

func (h OverlayIPv4) IP() net.IP {
	return net.IP(h)
}

func (h OverlayIPv4) Port() uint16 {
	return 0
}

func (h OverlayIPv4) String() string {
	return h.IP().String()
}

func (h OverlayIPv4) Type() Type {
	return OverlayTypeIPv4
}

// Overlay IPv6 type
// *****************************************
var _ OverlayAddr = (OverlayIPv6)(nil)

type OverlayIPv6 net.IP

func (h OverlayIPv6) Copy() OverlayAddr {
	return OverlayIPv6(append(net.IP(nil), h...))
}

func (h OverlayIPv6) Eq(a OverlayAddr) bool {
	ha, ok := a.(OverlayIPv6)
	return ok && net.IP(h).Equal(net.IP(ha))
}

func (h OverlayIPv6) IP() net.IP {
	return net.IP(h)
}

func (h OverlayIPv6) Size() int {
	return OverlayLenIPv6
}

func (h OverlayIPv6) Port() uint16 {
	return 0
}

func (h OverlayIPv6) String() string {
	return h.IP().String()
}

func (h OverlayIPv6) Type() Type {
	return OverlayTypeIPv6
}

// Overlay IPv4 type
// *****************************************
var _ OverlayAddr = (OverlayIPv4)(nil)

type OverlayIPv4 net.IP

func (h OverlayIPv4) Copy() OverlayAddr {
	return OverlayIPv4(append(net.IP(nil), h...))
}

func (h OverlayIPv4) Eq(a OverlayAddr) bool {
	ha, ok := a.(OverlayIPv4)
	return ok && net.IP(h).Equal(net.IP(ha))
}

func (h OverlayIPv4) IP() net.IP {
	return net.IP(h)
}

func (h OverlayIPv4) Port() uint16 {
	return 0
}

func (h OverlayIPv4) String() string {
	return h.IP().String()
}

func (h OverlayIPv4) Type() Type {
	return OverlayTypeIPv4
}

// Overlay IPv6 type
// *****************************************
var _ OverlayAddr = (OverlayIPv6)(nil)

type OverlayIPv6 net.IP

func (h OverlayIPv6) Copy() OverlayAddr {
	return OverlayIPv6(append(net.IP(nil), h...))
}

func (h OverlayIPv6) Eq(a OverlayAddr) bool {
	ha, ok := a.(OverlayIPv6)
	return ok && net.IP(h).Equal(net.IP(ha))
}

func (h OverlayIPv6) IP() net.IP {
	return net.IP(h)
}

func (h OverlayIPv6) Size() int {
	return OverlayLenIPv6
}

func (h OverlayIPv6) Port() uint16 {
	return 0
}

func (h OverlayIPv6) String() string {
	return h.IP().String()
}

func (h OverlayIPv6) Type() Type {
	return OverlayTypeIPv6
}
*/
