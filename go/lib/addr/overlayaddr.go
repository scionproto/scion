// +build ignore

// Copyright 2018 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by olicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package addr

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
)

type OverlayAddr struct {
	l3 HostAddr
	l4 L4Info
}

func NewOverlayAddr(l3 HostAddr, l4 L4Info) (*OverlayAddr, error) {
	if l3 == nil {
		return nil, common.NewBasicError("L3 required", nil)
	} else if l3.Type() == HostTypeSVC {
		return nil, common.NewBasicError("SVC is not a valid overlay address", nil)
	}
	if l4 != nil && l4.Type() != common.L4UDP {
		return nil, common.NewBasicError("Unsupported L4 protocol", nil, "type", l4.Type())
	}
	return &OverlayAddr{l3: l3, l4: l4}, nil
}

func (a *OverlayAddr) L3() HostAddr {
	return a.l3
}

func (a *OverlayAddr) L4() L4Info {
	return a.l4
}

func (a *OverlayAddr) Type() overlay.Type {
	if a.l4 != nil {
		// must be UDP
		if a.l3.Type() == HostTypeIPv4 {
			return overlay.UDPIPv4
		} else {
			// must be IPv6
			return overlay.UDPIPv6
		}
	}
	if a.l3.Type() == HostTypeIPv4 {
		return overlay.IPv4
	}
	// must be IPv6
	return overlay.IPv6
}

func (a *OverlayAddr) Copy() *OverlayAddr {
	return &OverlayAddr{l3: a.l3.Copy(), l4: a.l4.Copy()}
}

func (a *OverlayAddr) Eq(b *OverlayAddr) bool {
	if (a == nil) && (b == nil) {
		return true
	}
	if (a == nil) || (b == nil) {
		return false
	}
	return a.l3.Eq(b.l3) && a.l4.Eq(b.l4)
}

func (a *OverlayAddr) Network() string {
	return a.Type().String()
}

func (a *OverlayAddr) String() string {
	return fmt.Sprintf("%s:%s", a.l3, a.l4)
}
