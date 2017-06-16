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

package drkey

import (
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
)

type InputType uint8

const (
	None  InputType = 0
	sIPv4 InputType = 1
	sIPv6 InputType = 2
	sSVC  InputType = 3
	IPv4  InputType = 4
	IPv6  InputType = 8
	SVC   InputType = 12

	IPv4IPv4 InputType = IPv4 | sIPv4
	IPv4IPv6 InputType = IPv4 | sIPv6
	IPv4SVC  InputType = IPv4 | sSVC

	IPv6IPv4 InputType = IPv6 | sIPv4
	IPv6IPv6 InputType = IPv6 | sIPv6
	IPv6SVC  InputType = IPv6 | sSVC

	SVCIPv4 InputType = SVC | sIPv4
	SVCIPv6 InputType = SVC | sIPv6
	SVCSVC  InputType = SVC | sSVC
)

func (t InputType) String() string {
	if t > SVCSVC {
		return fmt.Sprintf("UNKNOWN (%d)", t)
	}
	first := "None"
	second := "None"
	switch t & SVC {
	case IPv4:
		first = "IPv4"
	case IPv6:
		first = "IPv6"
	case SVC:
		first = "SVC"
	}
	switch t & sSVC {
	case sIPv4:
		second = "IPv4"
	case sIPv6:
		second = "IPv6"
	case sSVC:
		second = "SVC"
	}
	return fmt.Sprintf("%v - %v", first, second)
}

func (t InputType) RequiredLength() int {
	r := 0
	switch t & SVC {
	case IPv4:
		r += addr.HostLenIPv4
	case IPv6:
		r += addr.HostLenIPv6
	case SVC:
		r += addr.HostLenSVC
	}
	switch t & sSVC {
	case sIPv4:
		r += addr.HostLenIPv4
	case sIPv6:
		r += addr.HostLenIPv6
	case sSVC:
		r += addr.HostLenSVC
	}
	return r
}

func InputTypeFromHostTypes(first, second addr.HostAddrType) (InputType, *common.Error) {
	t := None
	if (first == addr.HostTypeNone) && (second != addr.HostTypeNone) {
		return t, common.NewError("First has to be set if second is set")
	}

	switch first {
	case addr.HostTypeNone:
	case addr.HostTypeIPv4:
		t |= IPv4
	case addr.HostTypeIPv6:
		t |= IPv6
	case addr.HostTypeSVC:
		t |= SVC
	}
	switch second {
	case addr.HostTypeNone:
	case addr.HostTypeIPv4:
		t |= sIPv4
	case addr.HostTypeIPv6:
		t |= sIPv6
	case addr.HostTypeSVC:
		t |= sSVC
	}
	return t, nil
}
