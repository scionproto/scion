// Copyright 2017 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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

//go:build go1.9
// +build go1.9

// Package conn implements underlay sockets.
package conn

import (
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Messages is a list of ipX.Messages. It is necessary to hide the type alias
// between ipv4.Message, ipv6.Message and socket.Message.
type Messages []ipv4.Message

// Conn describes the API for an underlay socket
type Conn interface {
	ReadBatch(Messages) (int, error)
	WriteTo([]byte, netip.AddrPort) (int, error)
	WriteBatch(Messages, int) (int, error)
	LocalAddr() netip.AddrPort
	RemoteAddr() netip.AddrPort
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	SetDeadline(time.Time) error
	Close() error
}

// Config customizes the behavior of an underlay socket.
type Config struct {
	// SendBufferSize is the size of the operating system send buffer, in bytes.
	// If zero, the operating system default is used.
	SendBufferSize int
	// ReceiveBufferSize is the size of the operating system receive buffer, in
	// bytes.
	ReceiveBufferSize int
}

// New opens a new underlay socket on the specified addresses.
//
// The config can be used to customize socket behavior.
func New(listen, remote netip.AddrPort, cfg *Config) (Conn, error) {
	a := listen
	if remote.IsValid() {
		a = remote
	}
	if !a.IsValid() {
		panic("either listen or remote must be set")
	}
	if a.Addr().Is4() {
		return newConnUDPIPv4(listen, remote, cfg)
	}
	return newConnUDPIPv6(listen, remote, cfg)
}

type connUDPIPv4 struct {
	connUDPBase
	pconn *ipv4.PacketConn
}

func newConnUDPIPv4(listen, remote netip.AddrPort, cfg *Config) (*connUDPIPv4, error) {
	cc := &connUDPIPv4{}
	if err := cc.initConnUDP("udp4", listen, remote, cfg); err != nil {
		return nil, err
	}
	cc.pconn = ipv4.NewPacketConn(cc.conn)
	return cc, nil
}

// ReadBatch reads up to len(msgs) packets, and stores them in msgs.
// It returns the number of packets read, and an error if any.
func (c *connUDPIPv4) ReadBatch(msgs Messages) (int, error) {
	n, err := c.pconn.ReadBatch(msgs, syscallMSG_WAITFORONE)
	return n, err
}

func (c *connUDPIPv4) WriteBatch(msgs Messages, flags int) (int, error) {
	return c.pconn.WriteBatch(msgs, flags)
}

// SetReadDeadline sets the read deadline associated with the endpoint.
func (c *connUDPIPv4) SetReadDeadline(t time.Time) error {
	return c.pconn.SetReadDeadline(t)
}

func (c *connUDPIPv4) SetWriteDeadline(t time.Time) error {
	return c.pconn.SetWriteDeadline(t)
}

func (c *connUDPIPv4) SetDeadline(t time.Time) error {
	return c.pconn.SetDeadline(t)
}

type connUDPIPv6 struct {
	connUDPBase
	pconn *ipv6.PacketConn
}

func newConnUDPIPv6(listen, remote netip.AddrPort, cfg *Config) (*connUDPIPv6, error) {
	cc := &connUDPIPv6{}
	if err := cc.initConnUDP("udp6", listen, remote, cfg); err != nil {
		return nil, err
	}
	cc.pconn = ipv6.NewPacketConn(cc.conn)
	return cc, nil
}

// ReadBatch reads up to len(msgs) packets, and stores them in msgs.
// It returns the number of packets read, and an error if any.
func (c *connUDPIPv6) ReadBatch(msgs Messages) (int, error) {
	n, err := c.pconn.ReadBatch(msgs, syscallMSG_WAITFORONE)
	return n, err
}

func (c *connUDPIPv6) WriteBatch(msgs Messages, flags int) (int, error) {
	return c.pconn.WriteBatch(msgs, flags)
}

// SetReadDeadline sets the read deadline associated with the endpoint.
func (c *connUDPIPv6) SetReadDeadline(t time.Time) error {
	return c.pconn.SetReadDeadline(t)
}

func (c *connUDPIPv6) SetWriteDeadline(t time.Time) error {
	return c.pconn.SetWriteDeadline(t)
}

func (c *connUDPIPv6) SetDeadline(t time.Time) error {
	return c.pconn.SetDeadline(t)
}

type connUDPBase struct {
	conn   *net.UDPConn
	Listen netip.AddrPort
	Remote netip.AddrPort
	closed bool
}

func (c *connUDPBase) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *connUDPBase) WriteTo(b []byte, dst netip.AddrPort) (int, error) {
	if c.Remote.IsValid() {
		return c.conn.Write(b)
	}
	return c.conn.WriteToUDPAddrPort(b, dst)
}

func (c *connUDPBase) LocalAddr() netip.AddrPort {
	return c.Listen
}

func (c *connUDPBase) RemoteAddr() netip.AddrPort {
	return c.Remote
}

func (c *connUDPBase) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

// NewReadMessages allocates memory for reading IPv4 Linux network stack
// messages.
func NewReadMessages(n int) Messages {
	m := make(Messages, n)
	for i := range m {
		// Allocate a single-element, to avoid allocations when setting the buffer.
		m[i].Buffers = make([][]byte, 1)
	}
	return m
}
