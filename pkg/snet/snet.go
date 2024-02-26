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

// CPInfoProvider provides local-IA control-plane information
type CPInfoProvider interface {
	PortRange(ctx context.Context) (uint16, uint16, error)
	Interfaces(ctx context.Context) (map[uint16]*net.UDPAddr, error)
}

type Connector interface {
	// OpenUDP returns a PacketConn which listens on the specified address.
	// If address is nil or unspecified it listens on all available interfaces except
	// for multicast IP addresses.
	// If the address port is 0 a valid and free SCION/UDP port is automatically chosen. Otherwise,
	// the specified port must be a valid SCION/UDP port.
	OpenUDP(ctx context.Context, address *net.UDPAddr) (PacketConn, error)
}

type DefaultConnector struct {
	SCMPHandler    SCMPHandler
	Metrics        SCIONPacketConnMetrics
	CPInfoProvider CPInfoProvider
}

func (d *DefaultConnector) OpenUDP(ctx context.Context, addr *net.UDPAddr) (PacketConn, error) {
	var pconn *net.UDPConn
	var err error
	start, end, err := d.CPInfoProvider.PortRange(ctx)
	if err != nil {
		return nil, err
	}
	ifAddrs, err := d.CPInfoProvider.Interfaces(ctx)
	if err != nil {
		return nil, err
	}
	if addr.Port == 0 {
		pconn, err = listenUDPRange(addr, start, end)
	} else {
		// XXX(JordiSubira): We check that given port is within SCION/UDP
		// port range for the endhost.
		if addr.Port < int(start) || addr.Port > int(end) {
			return nil, serrors.New("Provided port is outside the SCION/UDP range",
				"start", start, "end", end, "port", addr.Port)
		}
		pconn, err = net.ListenUDP(addr.Network(), addr)
	}
	if err != nil {
		return nil, err
	}
	return &SCIONPacketConn{
		Conn:        pconn,
		SCMPHandler: d.SCMPHandler,
		Metrics:     d.Metrics,
		getLastHopAddr: func(id uint16) (*net.UDPAddr, error) {
			addr, ok := ifAddrs[id]
			if !ok {
				return nil, serrors.New("Interface number not found", "if", id)
			}
			return addr, nil
		},
	}, nil
}

func listenUDPRange(addr *net.UDPAddr, start, end uint16) (*net.UDPConn, error) {
	// XXX(JordiSubira): For now, we simply iterate on the complete SCION/UDP
	// range, taking the first unused port.
	for port := start; port < end; port++ {
		pconn, err := net.ListenUDP(addr.Network(), &net.UDPAddr{
			IP:   addr.IP,
			Port: int(port),
		})
		if err != nil {
			if !errors.Is(err, syscall.EADDRINUSE) {
				return nil, err
			}
			continue
		}
		return pconn, nil
	}
	return nil, serrors.New("There are no UDP ports available in range", "start", start, "end", end)
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
	LocalIA        addr.IA
	CPInfoProvider CPInfoProvider
	Connector      Connector
	// ReplyPather is used to create reply paths when reading packets on Conn
	// (that implements net.Conn). If unset, the default reply pather is used,
	// which parses the incoming path as a path.Path and reverses it.
	ReplyPather ReplyPather
	// Metrics holds the metrics emitted by the network.
	Metrics SCIONNetworkMetrics
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

// Listen opens a Conn. The returned connection's ReadFrom and WriteTo methods
// can be used to receive and send SCION packets with per-packet addressing.
// Parameter network must be "udp". If listen is unspecified address a suitable address
// will be chosen independently per packet. For finer-grained control, bind to a specific
// anycast address only.
//
// The context is used for connection setup, it doesn't affect the returned
// connection.
func (n *SCIONNetwork) Listen(ctx context.Context, network string, listen *net.UDPAddr,
	svc addr.SVC) (*Conn, error) {

	metrics.CounterInc(n.Metrics.Listens)

	if network != "udp" {
		return nil, serrors.New("Unknown network", "network", network)
	}

	packetConn, err := n.Connector.OpenUDP(ctx, listen)
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
	start, end, err := n.CPInfoProvider.PortRange(ctx)
	if err != nil {
		return nil, err
	}
	return newConn(conn, packetConn, replyPather, start, end), nil
}

// ResolveLocal returns the local IP address used for traffic destined to dst.
func ResolveLocal(dst net.IP) (net.IP, error) {
	udpAddr := net.UDPAddr{IP: dst, Port: 1}
	udpConn, err := net.DialUDP(udpAddr.Network(), nil, &udpAddr)
	if err != nil {
		return nil, err
	}
	defer udpConn.Close()
	srcIP := udpConn.LocalAddr().(*net.UDPAddr).IP
	return srcIP, nil
}
