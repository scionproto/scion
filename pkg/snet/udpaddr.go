// Copyright 2019 Anapaya Systems
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

package snet

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"inet.af/netaddr"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
)

var addrRegexpLegacy = regexp.MustCompile(`^(?P<ia>\d+-[\d:A-Fa-f]+),(?P<host>.+)$`)

// UDPAddr to be used when UDP host.
type UDPAddr struct {
	IA      addr.IA
	Path    DataplanePath
	NextHop *net.UDPAddr
	Host    *net.UDPAddr
}

// ParseUDPAddr converts an address string to a SCION address.
func ParseUDPAddr(s string) (*UDPAddr, error) {
	addr, err := parseUDPAddr(s)
	if err != nil {
		return parseUDPAddrLegacy(s)
	}
	return addr, nil
}

// The supported formats are based on the extensions of RFC 3986:
// https://scion.docs.anapaya.net/en/latest/uri.html#scion-udp
//
// Examples:
//  - [isd-as,ipv4]:port       (e.g., [1-ff00:0:110,192.0.2.1]:80)
//  - [isd-as,ipv6%zone]:port  (e.g., [1-ff00:0:110,2001:DB8::1%zone]:80)
func parseUDPAddr(s string) (*UDPAddr, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, serrors.WrapStr("invalid address: split host:port", err, "addr", s)
	}
	parts := strings.Split(host, ",")
	if len(parts) != 2 {
		return nil, serrors.New("invalid address: host parts invalid",
			"expected", 2, "actual", len(parts))
	}
	ia, err := addr.ParseIA(parts[0])
	if err != nil {
		return nil, serrors.WrapStr("invalid address: IA not parsable", err, "ia", ia)
	}
	ip, err := netip.ParseAddr(parts[1])
	if err != nil {
		return nil, serrors.WrapStr("invalid address: ip not parsable", err, "ip", parts[1])
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, serrors.WrapStr("invalid address: port invalid", err, "port", port)
	}
	udp := &net.UDPAddr{
		IP:   ip.AsSlice(),
		Zone: ip.Zone(),
		Port: p,
	}

	return &UDPAddr{IA: ia, Host: udp}, nil
}

// The legacy format of the SCION address URI encoding allows multiple different encodings.
// The supported legacy formats are:
//
// Recommended:
//  - isd-as,ipv4:port        (e.g., 1-ff00:0:300,192.168.1.1:8080)
//  - isd-as,[ipv6]:port      (e.g., 1-ff00:0:300,[f00d::1337]:8080)
//  - isd-as,[ipv6%zone]:port (e.g., 1-ff00:0:300,[f00d::1337%zone]:8080)
//
// Others:
//  - isd-as,[ipv4]:port (e.g., 1-ff00:0:300,[192.168.1.1]:8080)
//  - isd-as,[ipv4]      (e.g., 1-ff00:0:300,[192.168.1.1])
//  - isd-as,[ipv6]      (e.g., 1-ff00:0:300,[f00d::1337])
//  - isd-as,[ipv6%zone] (e.g., 1-ff00:0:300,[f00d::1337%zone])
//  - isd-as,ipv4        (e.g., 1-ff00:0:300,192.168.1.1)
//  - isd-as,ipv6        (e.g., 1-ff00:0:300,f00d::1337)
//  - isd-as,ipv6%zone   (e.g., 1-ff00:0:300,f00d::1337%zone)
//
// Not supported:
//  - isd-as,ipv6:port    (caveat if ipv6:port builds a valid ipv6 address,
//                         it will successfully parse as ipv6 without error)
func parseUDPAddrLegacy(s string) (*UDPAddr, error) {
	rawIA, rawHost, err := parseAddr(s)
	if err != nil {
		return nil, err
	}
	ia, err := addr.ParseIA(rawIA)
	if err != nil {
		return nil, serrors.WrapStr("invalid address: IA not parsable", err, "ia", ia)
	}
	if ipOnly(rawHost) {
		addr, err := net.ResolveIPAddr("ip", strings.Trim(rawHost, "[]"))
		if err != nil {
			return nil, serrors.WrapStr("invalid address: IP not resolvable", err)
		}
		return &UDPAddr{IA: ia, Host: &net.UDPAddr{IP: addr.IP, Port: 0, Zone: addr.Zone}}, nil
	}
	udp, err := net.ResolveUDPAddr("udp", rawHost)
	if err != nil {
		return nil, serrors.WrapStr("invalid address: host not parsable", err, "host", rawHost)
	}
	if udp.IP == nil {
		return nil, serrors.WrapStr("invalid address: ip not specified", err, "host", rawHost)
	}
	return &UDPAddr{IA: ia, Host: udp}, nil
}

// Network implements net.Addr interface.
func (a *UDPAddr) Network() string {
	return "udp/scion"
}

// String implements net.Addr interface.
func (a *UDPAddr) String() string {
	return fmt.Sprintf("%v,%s", a.IA, a.Host.String())
}

// GetPath returns a path with attached metadata.
func (a *UDPAddr) GetPath() (Path, error) {
	return &partialPath{
		dataplane:   a.Path,
		underlay:    a.NextHop,
		destination: a.IA,
	}, nil
}

// Set is used to satisfy the flag.Value and pflag.Value interface.
func (a *UDPAddr) Set(s string) error {
	other, err := ParseUDPAddr(s)
	if err != nil {
		return err
	}
	*a = *other
	return nil
}

// Type is used to satisfy the pflag.Value interface.
func (a *UDPAddr) Type() string {
	return "SCION UDP Address"
}

func CopyUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(a.IP[:0:0], a.IP...),
		Port: a.Port,
		Zone: a.Zone,
	}
}

func parseAddr(s string) (string, string, error) {
	match := addrRegexpLegacy.FindStringSubmatch(s)
	if len(match) != 3 {
		return "", "", serrors.New("invalid address: regex match failed", "addr", s)
	}
	left, right := strings.Count(s, "["), strings.Count(s, "]")
	if left != right {
		return "", "", serrors.New("invalid address: bracket count mismatch", "addr", s)
	}
	if strings.HasSuffix(match[2], ":") {
		return "", "", serrors.New("invalid address: trailing ':'", "addr", s)
	}
	return match[1], match[2], nil
}

func ipOnly(s string) bool {
	_, portErr := netaddr.ParseIPPort(s)
	_, ipErr := netaddr.ParseIP(strings.Trim(s, "[]"))
	return portErr != nil && ipErr == nil
}

// Copy creates a deep copy of the address.
func (a *UDPAddr) Copy() *UDPAddr {
	if a == nil {
		return nil
	}
	return &UDPAddr{
		IA:      a.IA,
		Path:    a.Path,
		NextHop: CopyUDPAddr(a.NextHop),
		Host:    CopyUDPAddr(a.Host),
	}
}
