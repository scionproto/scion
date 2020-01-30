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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
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

// UDPAddrFromString converts an address string of format isd-as,[ipaddr]:port
// (e.g., 1-ff00:0:300,192.168.1.1:80) to a SCION address.
func UDPAddrFromString(s string) (*UDPAddr, error) {
	parts, err := parseAddr(s)
	if err != nil {
		return nil, err
	}
	ia, err := addr.IAFromString(parts["ia"])
	if err != nil {
		return nil, serrors.WrapStr("invalid IA string", err, "ia", ia)
	}

	hostPortPart := parts["host"]
	host, portS, err := net.SplitHostPort(hostPortPart)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, serrors.New("invalid IP address string", "ip", host)
	}
	port, err := strconv.ParseUint(portS, 10, 16)
	if err != nil {
		return nil, serrors.WrapStr("invalid port in address", err, "host:port", hostPortPart)
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

func parseAddr(s string) (map[string]string, error) {
	result := make(map[string]string)
	match := addrRegexp.FindStringSubmatch(s)
	if len(match) == 0 {
		return nil, common.NewBasicError("Invalid address: regex match failed", nil, "addr", s)
	}
	for i, name := range addrRegexp.SubexpNames() {
		if i == 0 {
			continue
		}
		result[name] = match[i]
	}
	return result, nil
}
