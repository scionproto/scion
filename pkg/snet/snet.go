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
	"errors"
	"net"
	"syscall"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// Topology provides local-IA topology information
type Topology interface {
	LocalIA(ctx context.Context) (addr.IA, error)
	PortRange(ctx context.Context) (uint16, uint16, error)
	Interfaces(ctx context.Context) (map[uint16]*net.UDPAddr, error)
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
	// Topology provides local AS information, needed to handle sockets and
	// traffic.
	Topology Topology
	// ReplyPather is used to create reply paths when reading packets on Conn
	// (that implements net.Conn). If unset, the default reply pather is used,
	// which parses the incoming path as a path.Path and reverses it.
	ReplyPather ReplyPather
	// Metrics holds the metrics emitted by the network.
	Metrics SCIONNetworkMetrics
	// SCMPHandler describes the network behaviour upon receiving SCMP traffic.
	SCMPHandler       SCMPHandler
	PacketConnMetrics SCIONPacketConnMetrics
}

// OpenRaw returns a PacketConn which listens on the specified address.
// Nil or unspecified addresses are not supported.
// If the address port is 0 a valid and free SCION/UDP port is automatically chosen.
// Otherwise, the specified port must be a valid SCION/UDP port.
func (n *SCIONNetwork) OpenRaw(ctx context.Context, addr *net.UDPAddr) (PacketConn, error) {
	var pconn *net.UDPConn
	var err error
	if addr == nil || addr.IP.IsUnspecified() {
		return nil, serrors.New("nil or unspecified address is not permitted")
	}
	start, end, err := n.Topology.PortRange(ctx)
	if err != nil {
		return nil, err
	}
	ifAddrs, err := n.Topology.Interfaces(ctx)
	if err != nil {
		return nil, err
	}
	if addr.Port == 0 {
		pconn, err = listenUDPRange(addr, start, end)
	} else {
		// XXX(JordiSubira): We check that given port is within SCION/UDP
		// port range for the endhost.
		if addr.Port < int(start) || addr.Port > int(end) {
			return nil, serrors.New("provided port is outside the SCION/UDP range",
				"start", start, "end", end, "port", addr.Port)
		}
		pconn, err = net.ListenUDP(addr.Network(), addr)
	}
	if err != nil {
		return nil, err
	}
	return &SCIONPacketConn{
		Conn:         pconn,
		SCMPHandler:  n.SCMPHandler,
		Metrics:      n.PacketConnMetrics,
		interfaceMap: ifAddrs,
	}, nil
}

// Dial returns a SCION connection to remote. Parameter network must be "udp".
// The returned connection's Read and Write methods can be used to receive
// and send SCION packets.
// Remote address requires a path and the underlay next hop to be set if the
// destination is in a remote AS.
//
// The context is used for connection setup, it doesn't affect the returned
// connection.
func (n *SCIONNetwork) Dial(ctx context.Context, network string, listen *net.UDPAddr,
	remote *UDPAddr) (*Conn, error) {

	metrics.CounterInc(n.Metrics.Dials)
	if remote == nil {
		return nil, serrors.New("Unable to dial to nil remote")
	}
	conn, err := n.Listen(ctx, network, listen)
	if err != nil {
		return nil, err
	}
	conn.remote = remote.Copy()
	return conn, nil
}

// Listen opens a Conn. The returned connection's ReadFrom and WriteTo methods
// can be used to receive and send SCION packets with per-packet addressing.
// Parameter network must be "udp".
// Nil or unspecified addresses are not supported.
//
// The context is used for connection setup, it doesn't affect the returned
// connection.
func (n *SCIONNetwork) Listen(
	ctx context.Context,
	network string,
	listen *net.UDPAddr,
) (*Conn, error) {

	metrics.CounterInc(n.Metrics.Listens)
	if network != "udp" {
		return nil, serrors.New("Unknown network", "network", network)
	}
	packetConn, err := n.OpenRaw(ctx, listen)
	if err != nil {
		return nil, err
	}
	log.FromCtx(ctx).Debug("UDP socket openned on", "addr", packetConn.LocalAddr())
	return NewCookedConn(packetConn, n.Topology, n.ReplyPather, nil)
}

// NewCookedConn returns a "cooked" Conn. The Conn object can be used to
// send/receive SCION traffic with the usual methods.
// It takes as arguments a non-nil PacketConn and a non-nil Topology parameter.
// If replyPather is nil it will use a default ReplyPather.
func NewCookedConn(
	pconn PacketConn,
	topo Topology,
	replyPather ReplyPather,
	remote *UDPAddr,
) (*Conn, error) {
	localIA, err := topo.LocalIA(context.Background())
	if err != nil {
		return nil, err
	}
	local := &UDPAddr{
		IA:   localIA,
		Host: pconn.LocalAddr().(*net.UDPAddr),
	}
	if replyPather == nil {
		replyPather = DefaultReplyPather{}
	}
	start, end, err := topo.PortRange(context.Background())
	if err != nil {
		return nil, err
	}
	return newConn(pconn, replyPather, start, end, local, remote), nil
}

func listenUDPRange(addr *net.UDPAddr, start, end uint16) (*net.UDPConn, error) {
	// XXX(JordiSubira): For now, we simply iterate on the complete SCION/UDP
	// range, taking the first unused port.
	for port := start; port < end; port++ {
		pconn, err := net.ListenUDP(addr.Network(), &net.UDPAddr{
			IP:   addr.IP,
			Port: int(port),
		})
		if err == nil {
			return pconn, nil
		}
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		return nil, err
	}
	return nil, serrors.WrapStr("binding to port range", syscall.EADDRINUSE)
}
