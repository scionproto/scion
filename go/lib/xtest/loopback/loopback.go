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

// Package loopback defines a net.PacketConn implementation where sent messages
// are echoed back on the same connection.
package loopback

import (
	"io"
	"net"
	"time"
)

const (
	// Number of packets that can fit into Conn buffers until the writer blocks
	PktBufferSize = 16
)

// Connects a client-server app to itself to simplify testing.
type Conn struct {
	wire chan packet
}

type packet struct {
	b []byte
	a net.Addr
}

// New creates a new loopback connection with capacity PktBufferSize.
func New() *Conn {
	return &Conn{
		wire: make(chan packet, PktBufferSize),
	}
}

func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	if pkt, ok := <-c.wire; ok {
		n := copy(b, pkt.b)
		return n, pkt.a, nil
	}
	return 0, nil, io.EOF
}

func (c *Conn) WriteTo(b []byte, a net.Addr) (int, error) {
	c.wire <- packet{
		b: b,
		a: a,
	}
	return len(b), nil
}

func (c *Conn) Close() error {
	close(c.wire)
	return nil
}

// LocalAddr always returns nil.
func (c *Conn) LocalAddr() net.Addr {
	return nil
}

// SetDeadline is a NOP.
func (c *Conn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline is a NOP.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline is a NOP.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return nil
}

// Addr implements net.Addr. It always returns the same constant strings.
type Addr struct{}

// Network always returns "loopback".
func (a *Addr) Network() string {
	return "loopback"
}

// String always returns "loopback address".
func (a *Addr) String() string {
	return "loopback address"
}
