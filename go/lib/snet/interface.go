// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
)

type Network interface {
	Listen(ctx context.Context, network string, listen *net.UDPAddr, svc addr.HostSVC) (Conn, error)
	Dial(ctx context.Context, network string, listen *net.UDPAddr, remote *UDPAddr,
		svc addr.HostSVC) (Conn, error)
}

// Conn represents a SCION connection.
type Conn interface {
	Read(b []byte) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	Write(b []byte) (int, error)
	WriteTo(b []byte, address net.Addr) (int, error)
	Close() error
	LocalAddr() net.Addr
	SVC() addr.HostSVC
	// RemoteAddr returns the remote network address.
	RemoteAddr() net.Addr
	// SetDeadline sets read and write deadlines. Implements the net.Conn
	// SetDeadline method.
	SetDeadline(deadline time.Time) error
	SetReadDeadline(deadline time.Time) error
	SetWriteDeadline(deadline time.Time) error
}
