// Copyright 2016 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
// Copyright 2022 ETH Zurich, Anapaya Systems, SCION Association
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
	"net/netip"
)

// HostAddrType discriminates between different types of Host addresses.
type HostAddrType uint8

const (
	HostTypeNone HostAddrType = iota
	HostTypeIP
	HostTypeSVC
)

func (t HostAddrType) String() string {
	switch t {
	case HostTypeNone:
		return "None"
	case HostTypeIP:
		return "IP"
	case HostTypeSVC:
		return "SVC"
	}
	return fmt.Sprintf("UNKNOWN (%d)", t)
}

// Host represents the AS-local host identifier of a SCION address.
//
// Different address types (IPv4, IPv6, SVC) are all represented with
// this Host struct, discriminated with a Type() field.
//
// The zero value is a valid object with Host{}.Type() == HostTypeNone.
type Host struct {
	t   HostAddrType
	ip  netip.Addr
	svc SVC
}

// ParseHost parses s as either a service address or an IP address,
// returning the result as a Host address.
// s can either be a SVC address, in the format supported by ParseSVC(s),
// or an IP address in dotted decimal or IPv6 format.
func ParseHost(s string) (Host, error) {
	svc := ParseSVC(s)
	if svc != SvcNone {
		return HostSVC(svc), nil
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return Host{}, err
	}
	return HostIP(ip), nil
}

// MustParseHost calls ParseHost(s) and panics on error.
// It is intended for use in tests with hard-coded strings.
func MustParseHost(s string) Host {
	host, err := ParseHost(s)
	if err != nil {
		panic(err)
	}
	return host
}

// HostIP returns a Host address representing ip, with type HostTypeIP.
func HostIP(ip netip.Addr) Host {
	return Host{t: HostTypeIP, ip: ip}
}

// HostIPFromSlice returns the Host address representing ip, with type HostTypeIP.
//
// Hides the ok return value of netip.AddrFromSlice for convenience of use.
// If the slice's length is not 4 or 16, returns a Host representing an invalid
// IP address.
// TODO(matzf): return ok or ...?
func HostIPFromSlice(ip net.IP) Host {
	a, _ := netip.AddrFromSlice(ip)
	return HostIP(a)
}

// HostSvc returns a Host address representing svc, with type HostTypeSVC.
func HostSVC(svc SVC) Host {
	return Host{t: HostTypeSVC, svc: svc}
}

// Type returns the type of the address represented by h.
func (h Host) Type() HostAddrType {
	return h.t
}

// IP returns the IP address represented by h.
// Panics if h.Type() is not HostTypeIP.
func (h Host) IP() netip.Addr {
	if h.t != HostTypeIP {
		panic("IP called on non-IP address")
	}
	return h.ip
}

// SVC returns the SVC address represented by h.
// Panics if h.Type() is not HostTypeSVC.
func (h Host) SVC() SVC {
	if h.t != HostTypeSVC {
		panic("SVC called on non-SVC address")
	}
	return h.svc
}

func (h Host) String() string {
	switch h.Type() {
	case HostTypeNone:
		return "<None>"
	case HostTypeIP:
		return h.ip.String()
	case HostTypeSVC:
		return h.svc.String()
	}
	panic("unsupported host type")
}
