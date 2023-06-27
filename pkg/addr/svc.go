// Copyright 2022 SCION Association
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

package addr

import (
	"fmt"
	"strings"

	"github.com/scionproto/scion/pkg/private/serrors"
)

const (
	SvcDS       SVC = 0x0001
	SvcCS       SVC = 0x0002
	SvcWildcard SVC = 0x0010
	SvcNone     SVC = 0xffff

	SVCMcast SVC = 0x8000
)

var (
	// ErrUnsupportedSVCAddress indicates an unsupported SVC address.
	ErrUnsupportedSVCAddress = serrors.New("unsupported SVC address")
)

// SVC is a SCION service address.
// A service address is a short identifier for the service type, and a
// flag-bit for multicast.
// The package's SVC constant values are defined without multicast.
// The Multicast and Base methods set/unset the multicast flag.
type SVC uint16

// ParseSVC returns the SVC address corresponding to str. For anycast
// SVC addresses, use CS_A and DS_A; shorthand versions without
// the _A suffix (e.g., CS) also return anycast SVC addresses. For multicast,
// use CS_M, and DS_M.
func ParseSVC(str string) (SVC, error) {
	var m SVC
	switch {
	case strings.HasSuffix(str, "_A"):
		str = strings.TrimSuffix(str, "_A")
	case strings.HasSuffix(str, "_M"):
		str = strings.TrimSuffix(str, "_M")
		m = SVCMcast
	}
	switch str {
	case "DS":
		return SvcDS | m, nil
	case "CS":
		return SvcCS | m, nil
	case "Wildcard":
		return SvcWildcard | m, nil
	default:
		return SvcNone, serrors.New("invalid service address", "value", str)
	}
}

// IsMulticast returns the value of the multicast flag.
func (h SVC) IsMulticast() bool {
	return (h & SVCMcast) != 0
}

// Base returns the SVC identifier with the multicast flag unset.
func (h SVC) Base() SVC {
	return h & ^SVCMcast
}

// Multicast returns the SVC identifier with the multicast flag set.
func (h SVC) Multicast() SVC {
	return h | SVCMcast
}

func (h SVC) String() string {
	s := h.BaseString()
	if h.IsMulticast() {
		s += "_M"
	}
	return s
}

// BaseString returns the upper case name of the service. For unrecognized services, it
// returns "<SVC:Hex-Value>".
func (h SVC) BaseString() string {
	switch h.Base() {
	case SvcDS:
		return "DS"
	case SvcCS:
		return "CS"
	case SvcWildcard:
		return "Wildcard"
	default:
		return fmt.Sprintf("<SVC:0x%04x>", uint16(h))
	}
}
