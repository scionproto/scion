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

// Package snet implements interfaces net.Conn and net.PacketConn for SCION
// connections.
//
// New networking contexts can be created using NewNetwork. Calling the Dial or
// Listen methods on the networking context yields connections that run in that
// context.
//
// A connection can be created by calling Dial or Listen. For Dial, the
// remote address is fixed, meaning only Read and Write can be used. Attempting
// to ReadFrom or WriteTo a connection created by Dial is an invalid operation.
// For Listen, the remote address cannot be fixed. ReadFrom can be used to read
// from the connection and find out the sender's address; and WriteTo can be
// used to send a message to a chosen destination.
//
// Multiple networking contexts can share the same SCIOND.
//
// Write calls never return SCMP errors directly. If a write call caused an
// SCMP message to be received by the Conn, it can be inspected by calling
// Read. In this case, the error value is non-nil and can be type asserted to
// *OpError. Method SCMP() can be called on the error to extract the SCMP
// header.
package snet

import (
	"context"
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// Controler provides local-IA control-plane information
type Controler interface {
	PortRange() (uint16, uint16)
}

type Connector interface {
	OpenUDP(address *net.UDPAddr) (PacketConn, error)
}

type DefaultConnector struct {
	SCMPHandler SCMPHandler
	Metrics     SCIONPacketConnMetrics
}

func (d *DefaultConnector) OpenUDP(addr *net.UDPAddr) (PacketConn, error) {
	pconn, err := net.ListenUDP(addr.Network(), addr)
	if err != nil {
		return nil, err
	}
	return &SCIONPacketConn{
		Conn:        pconn,
		SCMPHandler: d.SCMPHandler,
		Metrics:     d.Metrics,
	}, nil
}

var _ Network = (*SCIONNetwork)(nil)

type SCIONNetworkMetrics struct {
	// Dials records the total number of Dial calls received by the network.
	Dials metrics.Counter
	// Listens records the total number of Listen calls received by the network.
	Listens metrics.Counter
}

// SCIONNetwork is the SCION networking context.
type SCIONNetwork struct {
	LocalIA   addr.IA
	Controler Controler
	Connector Connector
	// ReplyPather is used to create reply paths when reading packets on Conn
	// (that implements net.Conn). If unset, the default reply pather is used,
	// which parses the incoming path as a path.Path and reverses it.
	ReplyPather ReplyPather
	// Metrics holds the metrics emitted by the network.
	Metrics SCIONNetworkMetrics
}

// Dial returns a SCION connection to remote. Nil values for listen are not
// supported yet. Parameter network must be "udp". The returned connection's
// Read and Write methods can be used to receive and send SCION packets.
// Remote address requires a path and the underlay net hop to be set if the
// destination is in a remote AS.
//
// The context is used for connection setup, it doesn't affect the returned
// connection.
func (n *SCIONNetwork) Dial(ctx context.Context, network string, listen *net.UDPAddr,
	remote *UDPAddr, svc addr.SVC) (*Conn, error) {

	metrics.CounterInc(n.Metrics.Dials)
	if remote == nil {
		return nil, serrors.New("Unable to dial to nil remote")
	}
	conn, err := n.Listen(ctx, network, listen, svc)
	if err != nil {
		return nil, err
	}
	conn.remote = remote.Copy()
	return conn, nil
}

// Listen opens a PacketConn. The returned connection's ReadFrom and WriteTo methods
// can be used to receive and send SCION packets with per-packet addressing.
// Parameter network must be "udp".
//
// The context is used for connection setup, it doesn't affect the returned
// connection.
func (n *SCIONNetwork) Listen(ctx context.Context, network string, listen *net.UDPAddr,
	svc addr.SVC) (*Conn, error) {

	metrics.CounterInc(n.Metrics.Listens)

	if network != "udp" {
		return nil, serrors.New("Unknown network", "network", network)
	}

	packetConn, err := n.Connector.OpenUDP(listen)
	if err != nil {
		return nil, err
	}

	log.FromCtx(ctx).Debug("UDP socket openned on", "addr", packetConn.LocalAddr())

	conn := scionConnBase{
		scionNet: n,
		svc:      svc,
		listen: &UDPAddr{
			IA:   n.LocalIA,
			Host: packetConn.LocalAddr().(*net.UDPAddr),
		},
	}

	replyPather := n.ReplyPather
	if replyPather == nil {
		replyPather = DefaultReplyPather{}
	}
	return newConn(conn, packetConn, replyPather, n.Controler), nil
}
