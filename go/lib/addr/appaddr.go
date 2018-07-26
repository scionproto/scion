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

package addr

import (
	"fmt"
	"net"
)

// AppAddr
type AppAddrType uint8

const (
	AppAddrTypeNone AppAddrType = iota
	AppAddrTypeIPv4
	AppAddrTypeIPv6
	AppAddrTypeSVC
	AppAddrTypeUDPIPv4
	AppAddrTypeUDPIPv6
)

func (t AppAddrType) String() string {
	switch t {
	case AppAddrTypeIPv4:
		return "IPv4"
	case AppAddrTypeIPv6:
		return "IPv6"
	case AppAddrTypeSVC:
		return "SVC"
	case AppAddrTypeUDPIPv4:
		return "UDPIPv4"
	case AppAddrTypeUDPIPv6:
		return "UDPIPv6"
	}
	return fmt.Sprintf("UNKNOWN (%d)", t)
}

type AppAddr interface {
	Copy() AppAddr
	Type() AppAddrType
	Eq(AppAddr) bool
	Addr() HostAddr
	Port() uint16
	Network() string
	String() string
}

func NewAppAddr(host HostAddr, port uint16) AppAddr {
	var addr AppAddr
	ap := addrPort{addr: host, port: port}
	if port != 0 {
		switch host.(type) {
		case HostIPv4:
			addr = AppAddrUDPIPv4{ap}
		case HostIPv6:
			addr = AppAddrUDPIPv6{ap}
		}
	} else {
		switch host.(type) {
		case HostIPv4:
			addr = AppAddrIPv4{ap}
		case HostIPv6:
			addr = AppAddrIPv6{ap}
		case HostSVC:
			addr = AppAddrSVC{ap}
		}
	}
	return addr
}

func ToAppAddr(a net.Addr) AppAddr {
	switch v := a.(type) {
	case AppAddrIPv4:
		return v
	case AppAddrIPv6:
		return v
	case AppAddrSVC:
		return v
	case AppAddrUDPIPv4:
		return v
	case AppAddrUDPIPv6:
		return v
	}
	return nil
}

// AppAddrIPv4
type AppAddrIPv4 struct {
	addrPort
}

func NewAppAddrIPv4(ip net.IP) AppAddr {
	return AppAddrIPv4{addrPort{addr: HostIPv4(ip), port: 0}}
}

func (a AppAddrIPv4) Copy() AppAddr {
	return AppAddrIPv4{a.addrPort.cp()}
}

func (a AppAddrIPv4) Type() AppAddrType {
	return AppAddrTypeIPv4
}

func (a AppAddrIPv4) Eq(app AppAddr) bool {
	b, ok := app.(AppAddrIPv4)
	return ok && a.addrPort.eq(b.addrPort)
}

func (a AppAddrIPv4) Network() string {
	return "AppAddr"
}

func (a AppAddrIPv4) String() string {
	return fmt.Sprintf("%s", a.Addr())
}

// AppAddrIPv6
type AppAddrIPv6 struct {
	addrPort
}

func NewAppAddrIPv6(ip net.IP) AppAddr {
	return AppAddrIPv6{addrPort{addr: HostIPv6(ip), port: 0}}
}

func (a AppAddrIPv6) Copy() AppAddr {
	return AppAddrIPv6{a.addrPort.cp()}
}

func (a AppAddrIPv6) Type() AppAddrType {
	return AppAddrTypeIPv6
}

func (a AppAddrIPv6) Eq(app AppAddr) bool {
	b, ok := app.(AppAddrIPv6)
	return ok && a.addrPort.eq(b.addrPort)
}

func (a AppAddrIPv6) Network() string {
	return "AppAddr"
}

func (a AppAddrIPv6) String() string {
	return fmt.Sprintf("%s", a.Addr())
}

// AppAddrSVC
type AppAddrSVC struct {
	addrPort
}

func NewAppAddrSVC(svc HostSVC) AppAddr {
	return AppAddrSVC{addrPort{addr: HostSVC(svc), port: 0}}
}

func (a AppAddrSVC) Copy() AppAddr {
	return AppAddrSVC{a.addrPort.cp()}
}

func (a AppAddrSVC) Type() AppAddrType {
	return AppAddrTypeSVC
}

func (a AppAddrSVC) Eq(app AppAddr) bool {
	b, ok := app.(AppAddrSVC)
	return ok && a.addrPort.eq(b.addrPort)
}

func (a AppAddrSVC) Network() string {
	return "AppAddr"
}

func (a AppAddrSVC) String() string {
	return fmt.Sprintf("%s", a.Addr())
}

// AppAddrUDPIPv4
type AppAddrUDPIPv4 struct {
	addrPort
}

func NewAppAddrUDPIPv4(ip net.IP, port uint16) AppAddr {
	return AppAddrUDPIPv4{addrPort{addr: HostIPv4(ip), port: port}}
}

func (a AppAddrUDPIPv4) Copy() AppAddr {
	return AppAddrUDPIPv4{a.addrPort.cp()}
}

func (a AppAddrUDPIPv4) Type() AppAddrType {
	return AppAddrTypeUDPIPv4
}

func (a AppAddrUDPIPv4) Eq(app AppAddr) bool {
	b, ok := app.(AppAddrUDPIPv4)
	return ok && a.addrPort.eq(b.addrPort)
}

func (a AppAddrUDPIPv4) Network() string {
	return "AppAddr"
}

func (a AppAddrUDPIPv4) String() string {
	return fmt.Sprintf("%s:%d", a.Addr(), a.Port())
}

// AppAddrUDPIPv6
type AppAddrUDPIPv6 struct {
	addrPort
}

func NewAppAddrUDPIPv6(ip net.IP, port uint16) AppAddr {
	return AppAddrUDPIPv6{addrPort{addr: HostIPv6(ip), port: port}}
}

func (a AppAddrUDPIPv6) Copy() AppAddr {
	return AppAddrUDPIPv6{a.addrPort.cp()}
}

func (a AppAddrUDPIPv6) Type() AppAddrType {
	return AppAddrTypeUDPIPv6
}

func (a AppAddrUDPIPv6) Eq(app AppAddr) bool {
	b, ok := app.(AppAddrUDPIPv6)
	return ok && a.addrPort.eq(b.addrPort)
}

func (a AppAddrUDPIPv6) Network() string {
	return "AppAddr"
}

func (a AppAddrUDPIPv6) String() string {
	return fmt.Sprintf("%s:%d", a.Addr(), a.Port())
}
