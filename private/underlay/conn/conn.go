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

//go:build go1.9 && linux
// +build go1.9,linux

// Package conn implements underlay sockets.
package conn

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/underlay/sockctrl"
)

const (
	// ReceiveBufferSize is the size of receive buffers used by the dispatcher.
	ReceiveBufferSize = 1 << 20
	// SendBufferSize is the size of the send buffers used by the dispatcher.
	SendBufferSize = 1 << 20
)

// Messages is a list of ipX.Messages. It is necessary to hide the type alias
// between ipv4.Message, ipv6.Message and socket.Message.
type Messages []ipv4.Message

// Conn describes the API for an underlay socket
type Conn interface {
	ReadFrom([]byte) (int, *net.UDPAddr, error)
	ReadBatch(Messages) (int, error)
	Write([]byte) (int, error)
	WriteTo([]byte, *net.UDPAddr) (int, error)
	WriteBatch(Messages, int) (int, error)
	LocalAddr() *net.UDPAddr
	RemoteAddr() *net.UDPAddr
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
func New(listen, remote *net.UDPAddr, cfg *Config) (Conn, error) {
	a := listen
	if remote != nil {
		a = remote
	}
	if listen == nil && remote == nil {
		panic("either listen or remote must be set")
	}
	if a.IP.To4() != nil {
		return newConnUDPIPv4(listen, remote, cfg)
	}
	return newConnUDPIPv6(listen, remote, cfg)
}

// OpenConn opens an underlay socket that tracks additional socket information
// such as packets dropped due to buffer full.
//
// Note that Go-style dual-stacked IPv4/IPv6 connections are not supported. If
// network is udp, it will be treated as udp4.
func OpenConn(addr *net.UDPAddr) (net.PacketConn, error) {
	// We cannot allow the Go standard library to open both types of sockets
	// because the socket options are specific to only one socket type, so we
	// degrade udp to only udp4.
	listeningAddr := copyUDPAddr(addr)
	if listeningAddr == nil {
		listeningAddr = &net.UDPAddr{
			IP: net.IPv4zero,
		}
	}
	if (listeningAddr.Network() == "udp" || listeningAddr.Network() == "udp4") &&
		listeningAddr.IP == nil {
		listeningAddr.IP = net.IPv4zero
	}
	if listeningAddr.Network() == "udp6" && listeningAddr.IP == nil {
		listeningAddr.IP = net.IPv6zero
	}

	// TODO(JordiSubira): Should we keep a default config or use the passed-through
	// configuration.
	c, err := New(listeningAddr, nil, &Config{
		SendBufferSize:    SendBufferSize,
		ReceiveBufferSize: ReceiveBufferSize,
	})
	if err != nil {
		return nil, serrors.WrapStr("unable to open conn", err)
	}

	return &underlayConnWrapper{Conn: c}, nil
}

type connUDPIPv4 struct {
	connUDPBase
	pconn *ipv4.PacketConn
}

func newConnUDPIPv4(listen, remote *net.UDPAddr, cfg *Config) (*connUDPIPv4, error) {
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
	n, err := c.pconn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
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

func newConnUDPIPv6(listen, remote *net.UDPAddr, cfg *Config) (*connUDPIPv6, error) {
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
	n, err := c.pconn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
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
	Listen *net.UDPAddr
	Remote *net.UDPAddr
	closed bool
}

func (cc *connUDPBase) initConnUDP(network string, laddr, raddr *net.UDPAddr, cfg *Config) error {
	var c *net.UDPConn
	var err error
	if raddr == nil {
		if c, err = net.ListenUDP(network, laddr); err != nil {
			return serrors.WrapStr("Error listening on socket", err,
				"network", network, "listen", laddr)
		}
	} else {
		if c, err = net.DialUDP(network, laddr, raddr); err != nil {
			return serrors.WrapStr("Error setting up connection", err,
				"network", network, "listen", laddr, "remote", raddr)
		}
	}

	// Set and confirm send buffer size
	if cfg.SendBufferSize != 0 {
		before, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		if err != nil {
			return serrors.WrapStr("Error getting SO_SNDBUF socket option (before)", err,
				"listen", laddr,
				"remote", raddr,
			)
		}
		target := cfg.SendBufferSize
		if err = c.SetWriteBuffer(target); err != nil {
			return serrors.WrapStr("Error setting send buffer size", err,
				"listen", laddr,
				"remote", raddr,
			)
		}
		after, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		if err != nil {
			return serrors.WrapStr("Error getting SO_SNDBUF socket option (after)", err,
				"listen", laddr,
				"remote", raddr,
			)
		}
		if after/2 < target {
			// Note: kernel doubles value passed in SetSendBuffer, value
			// returned is the doubled value
			log.Info("Send buffer size smaller than requested",
				"expected", target,
				"actual", after/2,
				"before", before/2,
			)
		}
	}

	// Set and confirm receive buffer size
	if cfg.ReceiveBufferSize != 0 {
		before, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		if err != nil {
			return serrors.WrapStr("Error getting SO_RCVBUF socket option (before)", err,
				"listen", laddr,
				"remote", raddr,
			)
		}
		target := cfg.ReceiveBufferSize
		if err = c.SetReadBuffer(target); err != nil {
			return serrors.WrapStr("Error setting recv buffer size", err,
				"listen", laddr,
				"remote", raddr,
			)
		}
		after, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		if err != nil {
			return serrors.WrapStr("Error getting SO_RCVBUF socket option (after)", err,
				"listen", laddr,
				"remote", raddr,
			)
		}
		if after/2 < target {
			// Note: kernel doubles value passed in SetReadBuffer, value
			// returned is the doubled value
			log.Info("Receive buffer size smaller than requested",
				"expected", target,
				"actual", after/2,
				"before", before/2,
			)
		}
	}

	cc.conn = c
	cc.Listen = c.LocalAddr().(*net.UDPAddr)
	cc.Remote = raddr
	return nil
}

func (c *connUDPBase) ReadFrom(b []byte) (int, *net.UDPAddr, error) {
	return c.conn.ReadFromUDP(b)
}

func (c *connUDPBase) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *connUDPBase) WriteTo(b []byte, dst *net.UDPAddr) (int, error) {
	if c.Remote != nil {
		return c.conn.Write(b)
	}
	return c.conn.WriteTo(b, dst)
}

func (c *connUDPBase) LocalAddr() *net.UDPAddr {
	return c.Listen
}

func (c *connUDPBase) RemoteAddr() *net.UDPAddr {
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

// underlayConnWrapper wraps a specialized underlay Conn into a net.PacketConn
// implementation. Only *net.UDPAddr addressing is supported.
type underlayConnWrapper struct {
	// Conn is the wrapped underlay connection object.
	Conn
}

func (o *underlayConnWrapper) ReadFrom(p []byte) (int, net.Addr, error) {
	return o.Conn.ReadFrom(p)
}

func (o *underlayConnWrapper) WriteTo(p []byte, a net.Addr) (int, error) {
	udpAddr, ok := a.(*net.UDPAddr)
	if !ok {
		return 0, serrors.New("address is not UDP", "addr", a)
	}
	return o.Conn.WriteTo(p, udpAddr)
}

func (o *underlayConnWrapper) Close() error {
	return o.Conn.Close()
}

func (o *underlayConnWrapper) LocalAddr() net.Addr {
	return o.Conn.LocalAddr()
}

func (o *underlayConnWrapper) SetDeadline(t time.Time) error {
	return o.Conn.SetDeadline(t)
}

func (o *underlayConnWrapper) SetReadDeadline(t time.Time) error {
	return o.Conn.SetReadDeadline(t)
}

func (o *underlayConnWrapper) SetWriteDeadline(t time.Time) error {
	return o.Conn.SetWriteDeadline(t)
}

func copyUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(a.IP[:0:0], a.IP...),
		Port: a.Port,
		Zone: a.Zone,
	}
}
