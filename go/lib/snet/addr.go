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

package snet

import (
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/spath"
)

type Addr interface {
	net.Addr
	GetIA() addr.IA
	GetHost() addr.HostAddr
	GetL4Port() uint16
	GetPath() *spath.Path
	GetNextHopHost() addr.HostAddr
	GetNextHopPort() uint16
	SetIA(addr.IA)
	SetHost(addr.HostAddr)
	SetL4Port(uint16)
	SetPath(path *spath.Path)
	SetNextHopHost(host addr.HostAddr)
	SetNextHopPort(port uint16)
	Comparable
	AddrFromString(s string) (Addr, error)
	Desc() string
	Copy() Addr
	Set(s string) error
}

type Comparable interface {
	EqAddr(r Addr) bool
}
