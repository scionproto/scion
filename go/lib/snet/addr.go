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
	"strings"

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
	parts := split(s)
	if len(parts) != 3 {
		return nil, common.NewError("Invalid address format")
	}
	ia, cerr := addr.IAFromString(parts[0])
	if cerr != nil {
		return nil, common.NewError("Invalid IA string", "ia", ia, "err", cerr)
	}
	ip := net.ParseIP(parts[1])
	if ip == nil {
		return nil, common.NewError("Invalid IP address string", "ip", parts[1])
	}
	port, err := strconv.ParseUint(parts[2], 10, 16)
	if err != nil {
		return nil, common.NewError("Invalid port string", "port", parts[2], "err", err)
	}
	return &Addr{IA: ia, Host: addr.HostFromIP(ip), Port: uint16(port)}, nil
}

func split(s string) []string {
	x := strings.Split(s, ",[")
	if len(x) != 2 {
		return nil
	}
	y := strings.Split(x[1], "]:")
	if len(y) != 2 {
		return nil
	}
	return append([]string{x[0]}, y...)
}
