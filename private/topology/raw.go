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

package topology

import (
	"net"
	"net/netip"
	"strconv"

	"github.com/scionproto/scion/pkg/private/serrors"
	jsontopo "github.com/scionproto/scion/private/topology/json"
)

func rawBRIntfLocalAddr(u *jsontopo.Underlay) (netip.AddrPort, error) {
	if (u.DeprecatedPublic != "" || u.DeprecatedBind != "") && u.Local != "" {
		return netip.AddrPort{},
			serrors.New(`deprecated "public" and "bind" fields cannot be combined with "local"`,
				"underlay", u)
	}

	// handle _deprecated_ "public" and "bind" fields
	if u.DeprecatedPublic != "" {
		ret, err := resolveAddrPort(u.DeprecatedPublic)
		if err != nil {
			return netip.AddrPort{}, err
		}
		if u.DeprecatedBind != "" {
			bindIP, err := netip.ParseAddr(u.DeprecatedBind)
			if err != nil {
				return netip.AddrPort{}, err
			}
			ret = netip.AddrPortFrom(bindIP.Unmap(), ret.Port())
		}
		return ret, nil
	}

	// the new normal, parse "local"
	return resolveAddrPortOrPort(u.Local)
}

// resolveAddrPortOrPort parses a string in the format "IP:port", "hostname:port" or just ":port".
func resolveAddrPortOrPort(s string) (netip.AddrPort, error) {
	rh, rp, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, serrors.Wrap("failed to split host port", err)
	}
	if rh == "" {
		port, err := strconv.ParseUint(rp, 10, 16)
		if err != nil {
			return netip.AddrPort{}, serrors.Wrap("failed to parse port", err)
		}
		return netip.AddrPortFrom(netip.Addr{}, uint16(port)), nil
	}
	return resolveAddrPort(s)
}

// resolveAddrPort parses a string in the format "IP:port" or "hostname:port".
func resolveAddrPort(s string) (netip.AddrPort, error) {
	// detour via "legacy" net.UDPAddr; there is no corresponding function for netip.AddrPort
	udpAddr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	a := udpAddr.AddrPort()
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port()), nil
}
