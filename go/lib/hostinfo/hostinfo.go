// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

package hostinfo

import (
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
)

// Host contains connectivity information for a host.
type Host struct {
	Addrs Addrs  `capnp:"addrs"`
	Port  uint16 `capnp:"port"`
}

// Addrs is an address union for use in capnp serializations.
type Addrs struct {
	IPv4 []byte `capnp:"ipv4"`
	IPv6 []byte `capnp:"ipv6"`
}

func FromHostAddr(host addr.HostAddr, port uint16) *Host {
	h := &Host{Port: port}
	if host.Type() == addr.HostTypeIPv4 {
		h.Addrs.IPv4 = host.IP()
	} else {
		h.Addrs.IPv6 = host.IP()
	}
	return h
}

func FromUDPAddr(addr net.UDPAddr) Host {
	if addr.IP.To4() != nil {
		return Host{
			Addrs: Addrs{
				IPv4: copyIP(addr.IP),
			},
			Port: uint16(addr.Port),
		}
	}
	return Host{
		Addrs: Addrs{
			IPv6: copyIP(addr.IP),
		},
		Port: uint16(addr.Port),
	}
}

func (h *Host) Host() addr.HostAddr {
	if len(h.Addrs.IPv4) > 0 {
		return addr.HostIPv4(h.Addrs.IPv4)
	}
	if len(h.Addrs.IPv6) > 0 {
		return addr.HostIPv6(h.Addrs.IPv6)
	}
	return nil
}

func (h *Host) UDP() *net.UDPAddr {
	if len(h.Addrs.IPv4) > 0 {
		return &net.UDPAddr{
			IP:   copyIP(h.Addrs.IPv4),
			Port: int(h.Port),
		}
	}
	if len(h.Addrs.IPv6) > 0 {
		return &net.UDPAddr{
			IP:   copyIP(h.Addrs.IPv6),
			Port: int(h.Port),
		}
	}
	return nil
}

func (h *Host) Underlay() *net.UDPAddr {
	return &net.UDPAddr{IP: h.Host().IP(), Port: int(h.Port)}
}

func (h *Host) Copy() *Host {
	if h == nil {
		return nil
	}
	res := &Host{Port: h.Port}
	res.Addrs.IPv4 = copyIP(h.Addrs.IPv4)
	res.Addrs.IPv6 = copyIP(h.Addrs.IPv6)
	return res
}

func (h *Host) String() string {
	return fmt.Sprintf("[%v]:%d", h.Host(), h.Port)
}

func copyIP(ip net.IP) net.IP {
	return append(ip[:0:0], ip...)
}
