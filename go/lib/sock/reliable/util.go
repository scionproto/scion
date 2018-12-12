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

import "net"

const (
	ErrNoAddress             = "no address found"
	ErrNoPort                = "missing port"
	ErrPayloadTooLong        = "payload too long"
	ErrIncompleteFrameHeader = "incomplete frame header"
	ErrBadFrameLength        = "bad frame length"
	ErrBadCookie             = "bad cookie"
	ErrBadAddressType        = "bad address type"
	ErrIncompleteAddress     = "incomplete IP address"
	ErrIncompletePort        = "incomplete UDP port"
	ErrIncompleteMessage     = "incomplete message"
	ErrBadLength             = "bad length"
	ErrBufferTooSmall        = "buffer too small"
)

func getAddressInformation(address *net.UDPAddr) (AddressType, int) {
	c := getAddressType(address)
	return c, c.TotalLength()
}

func getAddressType(address *net.UDPAddr) AddressType {
	if address == nil || address.IP == nil {
		return AddressTypeNone
	}
	if address.IP.To4() != nil {
		return AddressTypeIPv4
	}
	return AddressTypeIPv6
}

func getIPAddressType(ip net.IP) AddressType {
	if ip.To4() != nil {
		return AddressTypeIPv4
	}
	return AddressTypeIPv6
}

// normalizeIP returns a 4-byte slice for an IPv4 address, and 16-byte slice
// for an IPv6 address.
func normalizeIP(ip net.IP) net.IP {
	if ip := ip.To4(); ip != nil {
		return ip
	}
	return ip
}

type AddressType byte

const (
	AddressTypeNone AddressType = 0
	AddressTypeIPv4 AddressType = 1
	AddressTypeIPv6 AddressType = 2
)

// TotalLength includes address and port bytes. Unknown address codes return a
// length of 0.
func (c AddressType) TotalLength() int {
	return c.AddressLength() + c.PortLength()
}

func (c AddressType) AddressLength() int {
	switch c {
	case AddressTypeNone:
		return 0
	case AddressTypeIPv4:
		return 4
	case AddressTypeIPv6:
		return 16
	default:
		return 0
	}
}

func (c AddressType) PortLength() int {
	switch c {
	case AddressTypeNone:
		return 0
	case AddressTypeIPv4:
		return 2
	case AddressTypeIPv6:
		return 2
	default:
		return 0
	}
}

// IsValid returns true only for address types that are defined.
func (c AddressType) IsValid() bool {
	if c == AddressTypeNone || c == AddressTypeIPv4 || c == AddressTypeIPv6 {
		return true
	}
	return false
}
