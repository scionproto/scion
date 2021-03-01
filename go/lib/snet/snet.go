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
// A connection can be created by calling Dial or Listen; both functions
// register an address-port pair with the local dispatcher. For Dial, the
// remote address is fixed, meaning only Read and Write can be used. Attempting
// to ReadFrom or WriteTo a connection created by Dial is an invalid operation.
// For Listen, the remote address cannot be fixed. ReadFrom can be used to read
// from the connection and find out the sender's address; and WriteTo can be
// used to send a message to a chosen destination.
//
// Multiple networking contexts can share the same SCIOND and/or dispatcher.
//
// Write calls never return SCMP errors directly. If a write call caused an
// SCMP message to be received by the Conn, it can be inspected by calling
// Read. In this case, the error value is non-nil and can be type asserted to
// *OpError. Method SCMP() can be called on the error to extract the SCMP
// header.
//
// Important: not draining SCMP errors via Read calls can cause the dispatcher
// to shutdown the socket (see https://github.com/scionproto/scion/pull/1356).
// To prevent this on a Conn object with only Write calls, run a separate
// goroutine that continuously calls Read on the Conn.
package snet

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet/internal/metrics"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

var _ Network = (*SCIONNetwork)(nil)

// SCIONNetwork is the SCION networking context.
type SCIONNetwork struct {
	LocalIA    addr.IA
	Dispatcher PacketDispatcherService
}

// NewNetwork creates a new networking context.
func NewNetwork(ia addr.IA, dispatcher reliable.Dispatcher,
	revHandler RevocationHandler) *SCIONNetwork {

	return &SCIONNetwork{
		LocalIA: ia,
		Dispatcher: &DefaultPacketDispatcherService{
			Dispatcher: dispatcher,
			SCMPHandler: &DefaultSCMPHandler{
				RevocationHandler: revHandler,
			},
		},
	}
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
	remote *UDPAddr, svc addr.HostSVC) (*Conn, error) {

	metrics.M.Dials().Inc()
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

// Listen registers listen with the dispatcher. Nil values for listen are
// not supported yet. The returned connection's ReadFrom and WriteTo methods
// can be used to receive and send SCION packets with per-packet addressing.
// Parameter network must be "udp".
//
// The context is used for connection setup, it doesn't affect the returned
// connection.
func (n *SCIONNetwork) Listen(ctx context.Context, network string, listen *net.UDPAddr,
	svc addr.HostSVC) (*Conn, error) {

	metrics.M.Listens().Inc()

	if network != "udp" {
		return nil, serrors.New("Unknown network", "network", network)
	}

	// FIXME(scrye): If no local address is specified, we want to
	// bind to the address of the outbound interface on a random
	// free port. However, the current dispatcher version cannot
	// expose that address. Additionally, the dispatcher does not follow
	// normal operating system semantics for binding on 0.0.0.0 (it
	// considers it to be a fixed address instead of a wildcard). To avoid
	// misuse, disallow binding to nil or 0.0.0.0 addresses for now.
	if listen == nil {
		return nil, serrors.New("nil listen addr not supported")
	}
	if listen.IP == nil {
		return nil, serrors.New("nil listen IP not supported")
	}
	if listen.IP.IsUnspecified() {
		return nil, serrors.New("unspecified listen IP not supported")
	}
	conn := &scionConnBase{
		scionNet: n,
		svc:      svc,
		listen:   CopyUDPAddr(listen),
	}
	packetConn, port, err := conn.scionNet.Dispatcher.Register(ctx, n.LocalIA, listen, svc)
	if err != nil {
		return nil, err
	}
	if port != uint16(conn.listen.Port) {
		// Update port
		conn.listen.Port = int(port)
	}
	log.Debug("Registered with dispatcher", "addr", &UDPAddr{IA: n.LocalIA, Host: conn.listen})
	return newConn(conn, packetConn), nil
}
