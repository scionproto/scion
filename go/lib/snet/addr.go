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
	"fmt"
	"net"
	"regexp"
	"strconv"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

var _ net.Addr = (*Addr)(nil)

var addrRegexp = regexp.MustCompile("^(?P<ia>\\d+-\\d+),\\[(?P<host>[^\\]]+)\\]:(?P<port>\\d+)$")

type Addr struct {
	IA   *addr.ISD_AS
	Host addr.HostAddr
	Port uint16
}

func (a *Addr) Network() string {
	return "scion"
}

func (a *Addr) String() string {
	if a == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s,[%s]:%d", a.IA, a.Host, a.Port)
}

func (a *Addr) Copy() *Addr {
	if a == nil {
		return nil
	}
	return &Addr{
		IA:   a.IA.Copy(),
		Host: a.Host.Copy(),
		Port: a.Port}
}

// AddrFromString converts an address string of format isd-as,[ipaddr]:port
// (e.g., 1-10,[192.168.1.1]:80) to a SCION address.
func AddrFromString(s string) (*Addr, error) {
	parts, err := parseAddr(s)
	if err != nil {
		return nil, common.NewError("Unable to parse address", "err", err)
	}

	ia, cerr := addr.IAFromString(parts["ia"])
	if cerr != nil {
		return nil, common.NewError("Invalid IA string", "ia", ia, "err", cerr)
	}

	ip := net.ParseIP(parts["host"])
	if ip == nil {
		return nil, common.NewError("Invalid IP address string", "ip", parts["host"])
	}

	port, err := strconv.ParseUint(parts["port"], 10, 16)
	if err != nil {
		return nil, common.NewError("Invalid port string", "port", parts["port"], "err", err)
	}
	if port == 0 {
		return nil, common.NewError("Invalid port number", "port", parts["port"])
	}
	return &Addr{IA: ia, Host: addr.HostFromIP(ip), Port: uint16(port)}, nil
}

func parseAddr(s string) (map[string]string, error) {
	result := make(map[string]string)
	match := addrRegexp.FindStringSubmatch(s)
	// If we do not have all submatches (ia, host, port), return an error
	if len(match) != 4 {
		return nil, common.NewError("Invalid address", "addr", s)
	}
	for i, name := range addrRegexp.SubexpNames() {
		if i != 0 {
			result[name] = match[i]
		}
	}
	return result, nil
}
