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

package overlay

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
)

type Type int

const (
	Invalid Type = iota
	IPv4
	IPv6
	IPv46
	UDPIPv4
	UDPIPv6
	UDPIPv46
)

const (
	IPv4Name     = "IPv4"
	IPv6Name     = "IPv6"
	IPv46Name    = "IPv4+6"
	UDPIPv4Name  = "UDP/IPv4"
	UDPIPv6Name  = "UDP/IPv6"
	UDPIPv46Name = "UDP/IPv4+6"
)

func (o Type) String() string {
	switch o {
	case IPv4:
		return IPv4Name
	case IPv6:
		return IPv6Name
	case IPv46:
		return IPv46Name
	case UDPIPv4:
		return UDPIPv4Name
	case UDPIPv6:
		return UDPIPv6Name
	case UDPIPv46:
		return UDPIPv46Name
	default:
		return fmt.Sprintf("UNKNOWN (%d)", o)
	}
}

func TypeFromString(s string) (Type, error) {
	switch strings.ToLower(s) {
	case strings.ToLower(IPv4Name):
		return IPv4, nil
	case strings.ToLower(IPv6Name):
		return IPv6, nil
	case strings.ToLower(IPv46Name):
		return IPv46, nil
	case strings.ToLower(UDPIPv4Name):
		return UDPIPv4, nil
	case strings.ToLower(UDPIPv6Name):
		return UDPIPv6, nil
	case strings.ToLower(UDPIPv46Name):
		return UDPIPv46, nil
	default:
		return Invalid, common.NewBasicError("Unknown overlay type", nil, "type", s)
	}
}

func (ot Type) MarshalJSON() ([]byte, error) {
	return json.Marshal(ot.String())
}

func (ot Type) IsIPv4() bool {
	switch ot {
	case IPv4, IPv46, UDPIPv4, UDPIPv46:
		return true
	}
	return false
}

func (ot Type) IsIPv6() bool {
	switch ot {
	case IPv6, IPv46, UDPIPv6, UDPIPv46:
		return true
	}
	return false
}

func (ot Type) IsUDP() bool {
	switch ot {
	case UDPIPv4, UDPIPv6, UDPIPv46:
		return true
	}
	return false
}

func (ot Type) ToIP() Type {
	switch ot {
	case UDPIPv4:
		return IPv4
	case UDPIPv6:
		return IPv6
	case UDPIPv46:
		return IPv46
	}
	return ot
}

func (ot Type) To6() Type {
	if ot.IsUDP() {
		return UDPIPv6
	}
	return IPv6
}

func (ot Type) To4() Type {
	if ot.IsUDP() {
		return UDPIPv4
	}
	return IPv4
}

func OverlayFromIP(ip net.IP, ot Type) Type {
	if ip.To4() != nil {
		// Address is IPv4
		if ot.IsUDP() {
			return UDPIPv4
		}
		return IPv4
	}
	// Address is IPv6
	if ot.IsUDP() {
		return UDPIPv6
	}
	return IPv6
}
