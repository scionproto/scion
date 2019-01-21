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

package addr

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
)

type L4Info interface {
	Size() int
	Type() common.L4ProtocolType
	Port() uint16
	Copy() L4Info
	Equal(L4Info) bool
	String() string
}

type l4AddrInfo struct {
	pType common.L4ProtocolType
	port  uint16
}

func NewL4UDPInfo(p uint16) L4Info {
	return &l4AddrInfo{pType: common.L4UDP, port: p}
}

func NewL4SCMPInfo() L4Info {
	return &l4AddrInfo{pType: common.L4SCMP}
}

func NewL4TCPInfo(p uint16) L4Info {
	return &l4AddrInfo{pType: common.L4TCP, port: p}
}

func (l *l4AddrInfo) Size() int {
	return 2
}

func (l *l4AddrInfo) Type() common.L4ProtocolType {
	return l.pType
}

func (l *l4AddrInfo) Port() uint16 {
	return l.port
}

func (l *l4AddrInfo) Copy() L4Info {
	return &l4AddrInfo{pType: l.pType, port: l.port}
}

func (a *l4AddrInfo) Equal(other L4Info) bool {
	o, ok := other.(*l4AddrInfo)
	return ok && a.pType == o.pType && a.port == o.port
}

func (l *l4AddrInfo) String() string {
	return fmt.Sprintf("%d (%s)", l.port, l.pType)
}
