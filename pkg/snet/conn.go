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
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet/multihomed"
)

type OpError struct {
	typeCode slayers.SCMPTypeCode
	revInfo  *path_mgmt.RevInfo
}

func (e *OpError) RevInfo() *path_mgmt.RevInfo {
	return e.revInfo
}

func (e *OpError) Error() string {
	if e.revInfo == nil {
		return e.typeCode.String()
	}
	return fmt.Sprintf("%s (%s)", e.typeCode, e.revInfo)
}

var _ net.Conn = (*Conn)(nil)
var _ net.PacketConn = (*Conn)(nil)

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
// This is an advanced API, that allows fine-tuning of the Conn underlay functionality.
// The general methods for obtaining a Conn object are still SCIONNetwork.Listen and
// SCIONNetwork.Dial.
func NewCookedConn(
	pconn PacketConn,
	topo Topology,
	options ...ConnOption,
) (*Conn, error) {
	o := apply(options)
	local := &UDPAddr{
		IA:   topo.LocalIA,
		Host: pconn.LocalAddr().(*net.UDPAddr),
	}
	hasSTUN := hasSTUNConn(pconn)

	// If acting as a client, find the local address of the interface used to reach
	// the NextHop toward the remote.
	if local.Host.IP.IsUnspecified() && o.remote != nil {
		localIP, err := multihomed.OutboundIP(o.remote.NextHop)
		if err != nil {
			return nil, serrors.Wrap(
				"Cannot find the local address", err,
				"local", local,
				"remote", o.remote)
		}
		local.Host.IP = localIP
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
			dispatchedPortStart: topo.PortRange.Start,
			dispatchedPortEnd:   topo.PortRange.End,
			hasSTUN:             hasSTUN,
		},
		scionConnReader: scionConnReader{
			conn:        pconn,
			buffer:      make([]byte, common.SupportedMTU),
			replyPather: o.replyPather,
			local:       local,
			hasSTUN:     hasSTUN,
		},
	}, nil
}

func (c *Conn) LocalAddr() net.Addr {
	return c.local
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.remote
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
type ConnOption func(o *options)

// WithReplyPather sets the reply pather for the connection.
// The reply pather is responsible for determining the path to send replies to.
// If the provided replyPather is not nil, it will be set as the reply pather for the connection.
func WithReplyPather(replyPather ReplyPather) ConnOption {
	return func(o *options) {
		if replyPather != nil {
			o.replyPather = replyPather
		}
	}
}

// WithRemote sets the remote address for the connection.
func WithRemote(addr *UDPAddr) ConnOption {
	return func(o *options) {
		o.remote = addr
	}
}

type options struct {
	replyPather ReplyPather
	remote      *UDPAddr
}

func apply(opts []ConnOption) options {
	o := options{
		replyPather: DefaultReplyPather{},
	}
	for _, option := range opts {
		option(&o)
	}
	return o
}

// hasSTUNConn checks if the provided PacketConn has STUN enabled.
func hasSTUNConn(pc PacketConn) bool {
	scionPacketConn, ok := pc.(*SCIONPacketConn)
	if !ok {
		return false
	}
	_, ok = scionPacketConn.conn.(*stunConn)
	return ok
}
