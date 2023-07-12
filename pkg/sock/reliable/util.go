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
)

type hostAddrType uint8

const (
	hostTypeNone = iota
	hostTypeIPv4
	hostTypeIPv6
	hostTypeSVC
)

func getAddressType(address *net.UDPAddr) hostAddrType {
	if address == nil || address.IP == nil {
		return hostTypeNone
	}
	return getIPAddressType(address.IP)
}

func getIPAddressType(ip net.IP) hostAddrType {
	if ip.To4() != nil {
		return hostTypeIPv4
	}
	return hostTypeIPv6
}

// normalizeIP returns a 4-byte slice for an IPv4 address, and 16-byte slice
// for an IPv6 address.
func normalizeIP(ip net.IP) net.IP {
	if ip := ip.To4(); ip != nil {
		return ip
	}
	return ip
}

func isValidReliableSockDestination(t hostAddrType) bool {
	return t == hostTypeNone || t == hostTypeIPv4 || t == hostTypeIPv6
}

func getAddressLength(t hostAddrType) int {
	switch t {
	case hostTypeNone:
		return 0
	case hostTypeIPv4:
		return 4
	case hostTypeIPv6:
		return 16
	case hostTypeSVC:
		return 2
	}
	return 0
}

func getPortLength(t hostAddrType) int {
	if t == hostTypeIPv4 || t == hostTypeIPv6 {
		return 2
	}
	return 0
}
