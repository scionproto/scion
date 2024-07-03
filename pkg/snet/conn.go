// Copyright 2017 ETH Zurich
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
	"syscall"
	"time"

	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
)

var _ net.Conn = (*Conn)(nil)
var _ net.PacketConn = (*Conn)(nil)
var _ syscall.Conn = (*Conn)(nil)

type Conn struct {
	conn PacketConn
	scionConnWriter
	scionConnReader

	// Local and remote SCION addresses (IA, L3, L4)
	local  *UDPAddr
	remote *UDPAddr
}

// NewCookedConn returns a "cooked" Conn. The Conn object can be used to
// send/receive SCION traffic with the usual methods.
// It takes as arguments a non-nil PacketConn and a non-nil Topology parameter.
// Nil or unspecified addresses for the PacketConn object are not supported.
// This is an advanced API, that allows fine-tunning of the Conn underlay functionality.
// The general methods for obtaining a Conn object are still SCIONNetwork.Listen and
// SCIONNetwork.Dial.
func NewCookedConn(
	pconn PacketConn,
	topo Topology,
	options ...ConnOption,
) (*Conn, error) {
	o := apply(options)
	localIA, err := topo.LocalIA(context.Background())
	if err != nil {
		return nil, err
	}
	local := &UDPAddr{
		IA:   localIA,
		Host: pconn.LocalAddr().(*net.UDPAddr),
	}
	if local.Host == nil || local.Host.IP.IsUnspecified() {
		return nil, serrors.New("nil or unspecified address is not supported.")
	}
	start, end, err := topo.PortRange(context.Background())
	if err != nil {
		return nil, err
	}
	return &Conn{
		conn:   pconn,
		local:  local,
		remote: o.remote,
		scionConnWriter: scionConnWriter{
			conn:                pconn,
			buffer:              make([]byte, common.SupportedMTU),
			local:               local,
			remote:              o.remote,
			dispatchedPortStart: start,
			dispatchedPortEnd:   end,
		},
		scionConnReader: scionConnReader{
			conn:        pconn,
			buffer:      make([]byte, common.SupportedMTU),
			replyPather: o.replyPather,
			scmpHandler: o.scmpHandler,
			local:       local,
		},
	}, nil
}

func (c *Conn) LocalAddr() net.Addr {
	return c.local
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *Conn) SyscallConn() (syscall.RawConn, error) {
	return c.conn.SyscallConn()
}

func (c *Conn) SetReadBuffer(n int) error {
	c.conn.SetReadBuffer(n)
	return nil
}

func (c *Conn) SetWriteBuffer(n int) error {
	c.conn.SetWriteBuffer(n)
	return nil
}

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.scionConnReader.SetReadDeadline(t); err != nil {
		return err
	}
	if err := c.scionConnWriter.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

// ConnOption is a functional option type for configuring a Conn.
type ConnOption func(o *connOptions)

// WithReplyPather sets the reply pather for the connection.
// The reply pather is responsible for determining the path to send replies to.
// If this option is not provided, DefaultReplyPather is used.
func WithReplyPather(replyPather ReplyPather) ConnOption {
	return func(o *connOptions) {
		o.replyPather = replyPather
	}
}

// WithSCMPHandler sets the SCMP handler for the connection.
// The SCMP handler is a callback to react to SCMP messages, specifically to error messages.
func WithSCMPHandler(scmpHandler SCMPHandler) ConnOption {
	return func(o *connOptions) {
		o.scmpHandler = scmpHandler
	}
}

// WithRemote sets the remote address for the connection.
// This only applies to NewCookedConn, but not Dial/Listen.
func WithRemote(addr *UDPAddr) ConnOption {
	return func(o *connOptions) {
		o.remote = addr
	}
}

type connOptions struct {
	replyPather ReplyPather
	scmpHandler SCMPHandler
	remote      *UDPAddr
}

func apply(opts []ConnOption) connOptions {
	o := connOptions{}
	for _, option := range opts {
		option(&o)
	}
	if o.replyPather == nil {
		o.replyPather = DefaultReplyPather{}
	}
	return o
}
