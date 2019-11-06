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

package overlay

import (
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
)

type OverlayAddr struct {
	l3 addr.HostAddr
	l4 uint16
}

func NewOverlayAddr(l3 addr.HostAddr, l4 uint16) (*OverlayAddr, error) {
	if l3 == nil {
		return nil, serrors.New("L3 required")
	}
	switch l3.Type() {
	case addr.HostTypeIPv4, addr.HostTypeIPv6:
	default:
		return nil, common.NewBasicError("Unsupported L3 protocol", nil, "type", l3.Type())
	}
	return &OverlayAddr{l3: l3, l4: l4}, nil
}

func (a *OverlayAddr) L3() addr.HostAddr {
	return a.l3
}

func (a *OverlayAddr) L4() uint16 {
	return a.l4
}

func (a *OverlayAddr) Type() Type {
	if a.l3.Type() == addr.HostTypeIPv4 {
		return UDPIPv4
	} else {
		// must be IPv6
		return UDPIPv6
	}
}

func (a *OverlayAddr) Copy() *OverlayAddr {
	if a == nil {
		return nil
	}
	return &OverlayAddr{l3: a.l3.Copy(), l4: a.l4}
}

func (a *OverlayAddr) Equal(o *OverlayAddr) bool {
	if (a == nil) || (o == nil) {
		return a == o
	}
	if a.l3 != nil {
		if !a.l3.Equal(o.l3) {
			return false
		}
	} else if o.l3 != nil {
		if !o.l3.Equal(a.l3) {
			return false
		}
	}
	return o.l4 == a.l4
}

func (a *OverlayAddr) Network() string {
	return a.Type().String()
}

func (a *OverlayAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	return fmt.Sprintf("[%s]:%d", a.l3, a.l4)
}

func (a *OverlayAddr) ToUDPAddr() *net.UDPAddr {
	if a.l3 == nil {
		return nil
	}
	return &net.UDPAddr{IP: a.l3.IP(), Port: int(a.l4)}
}
