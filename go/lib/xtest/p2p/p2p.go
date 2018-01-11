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

// Package p2p (point to point) defines a net.PacketConn implementation where
// messages are exchanged via channels.
package p2p

import (
	"io"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/common"
)

type Conn struct {
	send chan packet
	recv chan packet
}

const (
	// Number of packets that can fit into Conn buffers until the writer blocks
	PktBufferSize = 16
)

// New creates two paired connection objects. A message sent on the first conn
// is received on the second conn, and viceversa.
func New() (*Conn, *Conn) {
	a2b := make(chan packet, PktBufferSize)
	b2a := make(chan packet, PktBufferSize)
	a2bConn := &Conn{
		send: a2b,
		recv: b2a,
	}
	b2aConn := &Conn{
		send: b2a,
		recv: a2b,
	}
	return a2bConn, b2aConn
}

func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	if pkt, ok := <-c.recv; ok {
		n := copy(b, pkt.b)
		return n, pkt.a, nil
	}
	return 0, nil, io.EOF
}

func (c *Conn) WriteTo(b []byte, a net.Addr) (n int, err error) {
	// Panicking here is possible if a goroutine calls Close() thus closing the
	// channel, and another goroutine calls WriteTo afterwards and attempts to
	// write to it. If this happens, we recover and return an error.
	defer func() {
		if r := recover(); r != nil {
			err = common.NewBasicError("p2p conn closed", nil)
		}
	}()
	c.send <- packet{b: dup(b), a: a}
	return len(b), nil
}

func (c *Conn) Close() error {
	close(c.send)
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

type packet struct {
	b []byte
	a net.Addr
}

type Addr struct{}

// Network always returns "p2p".
func (a *Addr) Network() string {
	return "p2p"
}

// String always returns "p2p address".
func (a *Addr) String() string {
	return "p2p address"
}

func dup(b []byte) []byte {
	return append([]byte{}, b...)
}
