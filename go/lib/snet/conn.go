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
)

type Conn interface {
	net.Conn
	BindAddr() net.Addr
	BindSnetAddr() Addr
	LocalSnetAddr() Addr
	RemoteSnetAddr() Addr
	SVC() addr.HostSVC
	ReadFromSCION(b []byte) (int, Addr, error)
	WriteToSCION(b []byte, raddr Addr) (int, error)
	ReadFrom(b []byte) (n int, addr net.Addr, err error)
	WriteTo(b []byte, addr net.Addr) (n int, err error)
}
