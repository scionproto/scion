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

// Package p2p (point to point) provides a net.PacketConn wrapper around
// net.Pipe().
package p2p

import (
	"net"
)

// NewConns creates two paired network connections by calling net.Pipe. For more
// information on how the connections behave, see net.Pipe.
func NewConns() (net.Conn, net.Conn) {
	return net.Pipe()
}

// NewPacketConns creates two net.PacketConn implementations by wrapping over
// net.Conn's created via net.Pipe(). Addresses in WriteTo calls are ignored,
// and addresses returned by ReadFrom are always nil.
func NewPacketConns() (net.PacketConn, net.PacketConn) {
	c1, c2 := net.Pipe()
	return &conn{Conn: c1}, &conn{Conn: c2}
}

type conn struct {
	net.Conn
}

func (c *conn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(b)
	return n, nil, err
}

func (c *conn) WriteTo(b []byte, a net.Addr) (int, error) {
	return c.Conn.Write(b)
}
