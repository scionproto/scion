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
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/topology"
)

// HostInfo contains connectivity information for a host.
type HostInfo struct {
	Port  uint16
	Addrs struct {
		Ipv4 []byte
		Ipv6 []byte
	}
}

func FromHostAddr(host addr.HostAddr, port uint16) *HostInfo {
	h := &HostInfo{Port: port}
	if host.Type() == addr.HostTypeIPv4 {
		h.Addrs.Ipv4 = host.IP()
	} else {
		h.Addrs.Ipv6 = host.IP()
	}
	return h
}

func FromTopoAddr(topoAddr topology.TopoAddr) HostInfo {
	ipv4, port4 := topoAddrToIPv4AndPort(topoAddr)
	ipv6, port6 := topoAddrToIPv6AndPort(topoAddr)
	return buildHostInfo(ipv4, ipv6, port4, port6)
}

func FromTopoBRAddr(topoBRAddr topology.TopoBRAddr) HostInfo {
	ipv4, port4 := topoBRAddrToIPv4AndPort(topoBRAddr)
	ipv6, port6 := topoBRAddrToIPv6AndPort(topoBRAddr)
	return buildHostInfo(ipv4, ipv6, port4, port6)
}

func (h *HostInfo) Host() addr.HostAddr {
	if len(h.Addrs.Ipv4) > 0 {
		return addr.HostIPv4(h.Addrs.Ipv4)
	}
	if len(h.Addrs.Ipv6) > 0 {
		return addr.HostIPv6(h.Addrs.Ipv6)
	}
	return nil
}

func (h *HostInfo) Overlay() (*overlay.OverlayAddr, error) {
	var l4 addr.L4Info
	if h.Port != 0 {
		l4 = addr.NewL4UDPInfo(h.Port)
	}
	return overlay.NewOverlayAddr(h.Host(), l4)
}

func (h *HostInfo) String() string {
	return fmt.Sprintf("[%v]:%d", h.Host(), h.Port)
}

func topoAddrToIPv4AndPort(topoAddr topology.TopoAddr) (net.IP, uint16) {
	var ip net.IP
	var port uint16
	if pubAddr := topoAddr.PublicAddr(overlay.IPv4); pubAddr != nil {
		ip = pubAddr.L3.IP()
		port = pubAddr.L4.Port()
	}
	return ip, port
}

func topoAddrToIPv6AndPort(topoAddr topology.TopoAddr) (net.IP, uint16) {
	if pubAddr := topoAddr.PublicAddr(overlay.IPv6); pubAddr != nil {
		return pubAddr.L3.IP(), pubAddr.L4.Port()
	}
	return nil, 0
}

func topoBRAddrToIPv4AndPort(topoBRAddr topology.TopoBRAddr) (net.IP, uint16) {
	if topoBRAddr.IPv4 != nil {
		if v4Addr := topoBRAddr.IPv4.PublicOverlay; v4Addr != nil {
			return v4Addr.L3().IP(), v4Addr.L4().Port()
		}
	}
	return nil, 0
}

func topoBRAddrToIPv6AndPort(topoBRAddr topology.TopoBRAddr) (net.IP, uint16) {
	if topoBRAddr.IPv6 != nil {
		if v6Addr := topoBRAddr.IPv6.PublicOverlay; v6Addr != nil {
			return v6Addr.L3().IP(), v6Addr.L4().Port()
		}
	}
	return nil, 0
}

func buildHostInfo(ipv4, ipv6 net.IP, port4, port6 uint16) HostInfo {
	if port4 != 0 && port6 != 0 && port4 != port6 {
		// NOTE: https://github.com/scionproto/scion/issues/1842 will change
		// the behavior of this.
		log.Warn("port mismatch", "port4", port4, "port6", port6)
	}
	// XXX This assumes that Ipv4 and IPv6 use the same port!
	port := port4
	if port == 0 {
		port = port6
	}
	return HostInfo{
		Addrs: struct {
			Ipv4 []byte
			Ipv6 []byte
		}{
			Ipv4: ipv4,
			Ipv6: ipv6,
		},
		Port: port,
	}
}
