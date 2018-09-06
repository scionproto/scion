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

// FIXME(scrye): This file will go away once all its contents are baked into snet.

package snetproxy

import (
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

// FIXME(scrye): Temporary interface. This will be moved to snet when the
// module is integrated.
type Network interface {
	ListenSCIONWithBindSVC(network string,
		laddr, baddr *snet.Addr, svc addr.HostSVC, timeout time.Duration) (Conn, error)
	DialSCIONWithBindSVC(network string,
		laddr, raddr, baddr *snet.Addr, svc addr.HostSVC, timeout time.Duration) (Conn, error)
}

// FIXME(scrye): Temporary interface. This will be moved to snet when the
// module is integrated.
type Conn interface {
	Read(b []byte) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	ReadFromSCION(b []byte) (int, *snet.Addr, error)
	Write(b []byte) (int, error)
	WriteTo(b []byte, address net.Addr) (int, error)
	WriteToSCION(b []byte, address *snet.Addr) (int, error)
	Close() error
	LocalAddr() net.Addr
	BindAddr() net.Addr
	SVC() addr.HostSVC
	RemoteAddr() net.Addr
	SetDeadline(deadline time.Time) error
	SetReadDeadline(deadline time.Time) error
	SetWriteDeadline(deadline time.Time) error
}
