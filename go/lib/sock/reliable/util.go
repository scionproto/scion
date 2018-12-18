// Copyright 2018 ETH Zurich
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

package reliable

import (
	"net"

	"github.com/scionproto/scion/go/lib/addr"
)

func getAddressType(address *net.UDPAddr) addr.HostAddrType {
	if address == nil || address.IP == nil {
		return addr.HostTypeNone
	}
	return getIPAddressType(address.IP)
}

func getIPAddressType(ip net.IP) addr.HostAddrType {
	if ip.To4() != nil {
		return addr.HostTypeIPv4
	}
	return addr.HostTypeIPv6
}

// normalizeIP returns a 4-byte slice for an IPv4 address, and 16-byte slice
// for an IPv6 address.
func normalizeIP(ip net.IP) net.IP {
	if ip := ip.To4(); ip != nil {
		return ip
	}
	return ip
}

func isValidReliableSockDestination(t addr.HostAddrType) bool {
	return t == addr.HostTypeNone || t == addr.HostTypeIPv4 || t == addr.HostTypeIPv6
}

func getAddressLength(t addr.HostAddrType) int {
	n, _ := addr.HostLen(t)
	return int(n)
}

func getPortLength(t addr.HostAddrType) int {
	if t == addr.HostTypeIPv4 || t == addr.HostTypeIPv6 {
		return 2
	}
	return 0
}
