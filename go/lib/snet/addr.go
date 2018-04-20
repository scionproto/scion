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
	IA          addr.IA
	Host        addr.HostAddr
	L4Port      uint16
	Path        *spath.Path
	NextHopHost addr.HostAddr
	NextHopPort uint16
}

func (a *Addr) Network() string {
	return "scion"
}

func (a *Addr) String() string {
	if a == nil {
		return "<nil>"
	}
	s := fmt.Sprintf("%s,[%s]:%d", a.IA, a.Host, a.L4Port)
	return s
}

func (a *Addr) Desc() string {
	if a == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s Path: %t NextHop: [%v]:%d",
		a, a.Path != nil, a.NextHopHost, a.NextHopPort)
}

// EqAddr compares the IA/Host/L4port values with the supplied Addr
func (a *Addr) EqAddr(o *Addr) bool {
	if a == nil || o == nil {
		return a == o
	}
	if !a.IA.Eq(o.IA) {
		return false
	}
	if !addr.HostEq(a.Host, o.Host) {
		return false
	}
	return a.L4Port == o.L4Port
}

func (a *Addr) Copy() *Addr {
	if a == nil {
		return nil
	}
	newA := &Addr{
		IA:          a.IA,
		Host:        a.Host.Copy(),
		L4Port:      a.L4Port,
		NextHopPort: a.NextHopPort,
	}
	if a.Path != nil {
		newA.Path = a.Path.Copy()
	}
	if a.NextHopHost != nil {
		newA.NextHopHost = a.NextHopHost.Copy()
	}
	return newA
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
	ip := net.ParseIP(parts["host"])
	if ip == nil {
		return nil, common.NewBasicError("Invalid IP address string", nil, "ip", parts["host"])
	}
	var port uint64
	if parts["port"] != "" {
		var err error
		// skip the : (first character) from the port string
		port, err = strconv.ParseUint(parts["port"][1:], 10, 16)
		if err != nil {
			return nil, common.NewBasicError("Invalid port string", err, "port", parts["port"][1:])
		}
	}
	return &Addr{IA: ia, Host: addr.HostFromIP(ip), L4Port: uint16(port)}, nil
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
	a.IA, a.Host, a.L4Port = other.IA, other.Host, other.L4Port
	return nil
}
