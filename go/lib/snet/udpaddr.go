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
	"regexp"
	"strconv"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
)

var addrRegexp = regexp.MustCompile(`^(?P<ia>\d+-[\d:A-Fa-f]+),(?P<host>.+)$`)

// UDPAddr to be used when UDP host.
type UDPAddr struct {
	IA      addr.IA
	Path    *spath.Path
	NextHop *net.UDPAddr
	Host    *net.UDPAddr
}

// UDPAddrFromString converts an address string to a SCION address.
// The supported formats are:
//
// Recommended:
//  - isd-as,ipv4:port   (e.g., 1-ff00:0:300,192.168.1.1:8080)
//  - isd-as,[ipv6]:port (e.g., 1-ff00:0:300,[f00d::1337]:808)
//
// Others:
//  - isd-as,[ipv4]:port (e.g., 1-ff00:0:300,[192.168.1.1]:80)
//  - isd-as,[ipv4]      (e.g., 1-ff00:0:300,[192.168.1.1])
//  - isd-as,[ipv6]      (e.g., 1-ff00:0:300,[f00d::1337])
//  - isd-as,ipv4        (e.g., 1-ff00:0:300,192.168.1.1)
//  - isd-as,ipv6        (e.g., 1-ff00:0:300,f00d::1337)
//
// Not supported:
//  - isd-as,ipv6:port    (caveat if ipv6:port builds a valid ipv6 address,
//                         it will successfully parse as ipv6 without error)
func UDPAddrFromString(s string) (*UDPAddr, error) {
	rawIA, rawHost, err := parseAddr(s)
	if err != nil {
		return nil, err
	}
	ia, err := addr.IAFromString(rawIA)
	if err != nil {
		return nil, serrors.WrapStr("invalid address: IA not parsable", err, "ia", ia)
	}
	// First check if host is an IP without a port.
	if ip := net.ParseIP(strings.Trim(rawHost, "[]")); ip != nil {
		return &UDPAddr{IA: ia, Host: &net.UDPAddr{IP: ip, Port: 0}}, nil
	}

	rawIP, rawPort, err := net.SplitHostPort(rawHost)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(rawIP)
	if ip == nil {
		return nil, serrors.New("invalid address: no IP specified", "host", rawHost)
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil {
		return nil, serrors.New("invalid port", "host", rawHost)
	}
	return &UDPAddr{IA: ia, Host: &net.UDPAddr{IP: ip, Port: int(port)}}, nil
}

// Network implements net.Addr interface.
func (a *UDPAddr) Network() string {
	return "scion"
}

// String implements net.Addr interface.
func (a *UDPAddr) String() string {
	return fmt.Sprintf("%v,%s", a.IA, a.Host.String())
}

// GetPath returns a path with attached metadata.
func (a *UDPAddr) GetPath() (Path, error) {
	// Initialize path so it is always ready for use
	var p *spath.Path
	if a.Path != nil {
		p = a.Path.Copy()
		if err := p.InitOffsets(); err != nil {
			return nil, err
		}
	}
	return &partialPath{
		spath:       p,
		overlay:     a.NextHop,
		destination: a.IA,
	}, nil
}

// Set implements the flag.Value interface
func (a *UDPAddr) Set(s string) error {
	other, err := UDPAddrFromString(s)
	if err != nil {
		return err
	}
	*a = *other
	return nil
}

// Copy creates a deep copy of the address.
func (a *UDPAddr) Copy() *UDPAddr {
	if a == nil {
		return nil
	}
	return &UDPAddr{
		IA:      a.IA,
		Path:    a.Path.Copy(),
		NextHop: CopyUDPAddr(a.NextHop),
		Host:    CopyUDPAddr(a.Host),
	}
}

// CopyUDPAddr creates a deep copy of the net.UDPAddr.
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
	match := addrRegexp.FindStringSubmatch(s)
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
