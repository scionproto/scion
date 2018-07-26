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

package snet

import (
	"flag"
	"fmt"
	"net"
	"regexp"
	"strconv"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
)

var _ net.Addr = (*Addr)(nil)
var _ flag.Value = (*Addr)(nil)

var addrRegexp = regexp.MustCompile(
	`^(?P<ia>\d+-[\d:A-Fa-f]+),\[(?P<host>[^\]]+)\](?P<port>:\d+)?$`)

type Addr struct {
	IA      addr.IA
	Host    addr.AppAddr
	Path    *spath.Path
	NextHop addr.OverlayAddr
}

func (a *Addr) Network() string {
	return "scion"
}

func (a *Addr) String() string {
	if a == nil {
		return "<nil>"
	}
	if a.Host == nil {
		return fmt.Sprintf("%s,<nil>", a.IA)
	}
	return fmt.Sprintf("%s,[%v]:%d", a.IA, a.Host.Addr(), a.Host.Port())
}

func (a *Addr) Desc() string {
	if a == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s Path: %t NextHop: [%v]:%d", a, a.Path != nil,
		a.Host.Addr(), a.Host.Port())
}

// EqAddr compares the IA/Host/L4port values with the supplied Addr
func (a *Addr) EqAddr(b *Addr) bool {
	if a == nil || b == nil {
		return a == b
	}
	if !a.IA.Eq(b.IA) {
		return false
	}
	return a.Host.Eq(b.Host)
}

func (a *Addr) Copy() *Addr {
	if a == nil {
		return nil
	}
	newA := &Addr{
		IA:   a.IA,
		Host: a.Host.Copy(),
	}
	if a.Path != nil {
		newA.Path = a.Path.Copy()
	}
	if a.NextHop != nil {
		newA.NextHop = a.NextHop.Copy()
	}
	return newA
}

// UnmarshalText implements encoding.TextUnmarshaler
func (a *Addr) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*a = Addr{}
	}
	other, err := AddrFromString(string(text))
	if err != nil {
		return err
	}
	*a = *other
	return nil
}

func (a *Addr) IsZero() bool {
	return a.IA.IsZero() && a.Host == nil && a.Path == nil && a.NextHop == nil
}

// AddrFromString converts an address string of format isd-as,[ipaddr]:port
// (e.g., 1-ff00:0:300,[192.168.1.1]:80) to a SCION address.
func AddrFromString(s string) (*Addr, error) {
	parts, err := parseAddr(s)
	if err != nil {
		return nil, err
	}
	ia, err := addr.IAFromString(parts["ia"])
	if err != nil {
		return nil, common.NewBasicError("Invalid IA string", err, "ia", ia)
	}

	var hostAddr addr.HostAddr
	if hostSVC := addr.HostSVCFromString(parts["host"]); hostSVC != addr.SvcNone {
		hostAddr = hostSVC
	} else {
		ip := net.ParseIP(parts["host"])
		if ip == nil {
			return nil, common.NewBasicError("Invalid IP address string", nil, "ip", parts["host"])
		}
		hostAddr = addr.HostFromIP(ip)
	}

	var port uint16
	if parts["port"] != "" {
		// skip the : (first character) from the port string
		p, err := strconv.ParseUint(parts["port"][1:], 10, 16)
		if err != nil {
			return nil, common.NewBasicError("Invalid port string", err, "port", parts["port"][1:])
		}
		port = uint16(p)
	}
	return &Addr{IA: ia, Host: addr.NewAppAddr(hostAddr, port)}, nil
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

// This method implements flag.Value interface
func (a *Addr) Set(s string) error {
	other, err := AddrFromString(s)
	if err != nil {
		return err
	}
	a.IA, a.Host = other.IA, other.Host
	return nil
}
