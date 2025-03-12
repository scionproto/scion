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
	ip  netip.Addr
	svc SVC
	t   HostAddrType
}

// ParseHost parses s as either a service address or an IP address,
// returning the result as a Host address.
// s can either be a SVC address, in the format supported by ParseSVC(s),
// or an IP address in dotted decimal or IPv6 format.
func ParseHost(s string) (Host, error) {
	svc, err := ParseSVC(s)
	if err == nil {
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
		panic(fmt.Errorf("IP called on non-IP address: %d (%s)", h.t, h.t.String()))
	}
	return h.ip
}

// SVC returns the SVC address represented by h.
// Panics if h.Type() is not HostTypeSVC.
func (h Host) SVC() SVC {
	if h.t != HostTypeSVC {
		panic(fmt.Errorf("SVC called on non-SVC address: %d (%s)", h.t, h.t.String()))
	}
	return h.svc
}

func (h Host) String() string {
	switch t := h.Type(); t {
	case HostTypeNone:
		return "<None>"
	case HostTypeIP:
		return h.ip.String()
	case HostTypeSVC:
		return h.svc.String()
	default:
		panic(fmt.Errorf("unsupported host type: %d (%s)", t, t.String()))
	}
}

// Set implements flag.Value interface
func (h *Host) Set(s string) error {
	pH, err := ParseHost(s)
	if err != nil {
		return err
	}
	*h = pH
	return nil
}
