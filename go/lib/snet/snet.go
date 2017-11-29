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

// Package snet implements interfaces net.Conn and net.PacketConn for SCION
// connections.
//
// The default (package-wide) SCION network must first be initialized by
// calling Init. All future package scoped DialSCION and ListenSCION calls will
// use this initial context to get the local ISD-AS, dispatcher or sciond.
//
// A connection can be created by calling DialSCION or ListenSCION; both
// functions register an address-port pair with the local dispatcher. For Dial,
// the remote address is fixed, meaning only Read and Write can be used.
// Attempting to ReadFrom or WriteTo a connection created by Dial is an invalid
// operation. For Listen, the remote address cannot be fixed. ReadFrom,
// ReadFromSCION can be used to read from the connection and find out the
// sender's address; WriteTo and WriteToSCION can be used to send a message to
// a chosen destination.
//
// For applications that need to run in multiple ASes, new networking contexts
// can be created using NewNetwork. Calling the DialSCION or ListenSCION
// methods on the networking context yields connections that run in that context.
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
// to block (see Issue #1278). To prevent this on a Conn object with only Write
// calls, run a separate goroutine that continuously calls Read on the Conn.
package snet

import (
	"net"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/pathmgr"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/lib/sock/reliable"
)

var (
	// Default SCION networking context for package-level Dial and Listen
	DefNetwork *Network
)

// Init initializes the default SCION networking context.
func Init(ia *addr.ISD_AS, sPath string, dPath string) error {
	if DefNetwork != nil {
		return common.NewCError("Cannot initialize global SCION network twice")
	}

	network, err := NewNetwork(ia, sPath, dPath)
	if err != nil {
		return err
	}
	DefNetwork = network
	return nil
}

// IA returns the default ISD-AS
func IA() *addr.ISD_AS {
	if DefNetwork == nil {
		return nil
	}
	return DefNetwork.localIA.Copy()
}

// SCION networking context, containing local ISD-AS, SCIOND, Dispatcher and
// Path resolver.
type Network struct {
	sciondPath     string
	dispatcherPath string
	pathResolver   *pathmgr.PR
	localIA        *addr.ISD_AS
}

// NewNetwork creates a new networking context, on which future Dial or Listen
// calls can be made. The new connections use the SCIOND server at sPath, the
// dispatcher at dPath, and ia for the local ISD-AS.
func NewNetwork(ia *addr.ISD_AS, sPath string, dPath string) (*Network, error) {
	network := &Network{
		sciondPath:     sPath,
		dispatcherPath: dPath,
		localIA:        ia,
	}
	sd := sciond.NewService(sPath)
	timers := pathmgr.Timers{
		NormalRefire: time.Minute,
		ErrorRefire:  3 * time.Second,
		MaxAge:       time.Hour,
	}
	pathResolver, err := pathmgr.New(sd, timers, log.Root())
	if err != nil {
		return nil, common.NewCError("Unable to initialize path resolver", "err", err)
	}
	network.pathResolver = pathResolver
	return network, nil
}

// DialSCION returns a SCION connection to raddr. Nil values for laddr are not
// supported yet.  Parameter network must be "udp4". The returned connection's
// Read and Write methods can be used to receive and send SCION packets.
func (n *Network) DialSCION(network string, laddr *Addr, raddr *Addr) (*Conn, error) {
	return n.DialSCIONWithBindSVC(network, laddr, raddr, nil, addr.SvcNone)
}

// DialSCIONWithBindSVC returns a SCION connection to raddr. Nil values for laddr are not
// supported yet.  Parameter network must be "udp4". The returned connection's
// Read and Write methods can be used to receive and send SCION packets.
func (n *Network) DialSCIONWithBindSVC(network string, laddr, raddr, baddr *Addr,
	svc addr.HostSVC) (*Conn, error) {
	if raddr == nil {
		return nil, common.NewCError("Unable to dial to nil remote")
	}
	conn, err := n.ListenSCIONWithBindSVC(network, laddr, baddr, svc)
	if err != nil {
		return nil, err
	}
	conn.raddr = raddr.Copy()
	conn.sp, err = n.pathResolver.Watch(conn.laddr.IA, conn.raddr.IA)
	if err != nil {
		return nil, common.NewCError("Unable to establish path", "err", err)
	}
	return conn, nil
}

// ListenSCION registers laddr with the dispatcher. Nil values for laddr are
// not supported yet. The returned connection's ReadFrom and WriteTo methods
// can be used to receive and send SCION packets with per-packet addressing.
// Parameter network must be "udp4".
func (n *Network) ListenSCION(network string, laddr *Addr) (*Conn, error) {
	return n.ListenSCIONWithBindSVC(network, laddr, nil, addr.SvcNone)
}

// ListenSCIONWithBindSVC registers laddr with the dispatcher. Nil values for laddr are
// not supported yet. The returned connection's ReadFrom and WriteTo methods
// can be used to receive and send SCION packets with per-packet addressing.
// Parameter network must be "udp4".
func (n *Network) ListenSCIONWithBindSVC(network string, laddr, baddr *Addr,
	svc addr.HostSVC) (*Conn, error) {
	if network != "udp4" {
		return nil, common.NewCError("Network not implemented", "net", network)
	}
	// FIXME(scrye): If no local address is specified, we want to
	// bind to the address of the outbound interface on a random
	// free port. However, the current dispatcher version cannot
	// expose that address. Additionally, the dispatcher does not follow
	// normal operating system semantics for binding on 0.0.0.0 (it
	// considers it to be a fixed address instead of a wildcard). To avoid
	// misuse, disallow binding to nil or 0.0.0.0 addresses for now.
	if laddr == nil {
		return nil, common.NewCError("Nil laddr not supported")
	}
	if laddr.Host.Type() != addr.HostTypeIPv4 {
		return nil, common.NewCError("Supplied local address does not match network",
			"expected", addr.HostTypeIPv4, "actual", laddr.Host.Type())
	}
	if laddr.Host.IP().Equal(net.IPv4zero) {
		return nil, common.NewCError("Binding to 0.0.0.0 not supported")
	}
	conn := &Conn{
		net:        network,
		scionNet:   n,
		recvBuffer: make(common.RawBytes, BufSize),
		sendBuffer: make(common.RawBytes, BufSize),
		svc:        svc}

	// Initialize local bind address
	regAddr := &reliable.AppAddr{}
	var bindAddr *reliable.AppAddr
	// NOTE: keep nil address logic for now, even though we do not support
	// it yet
	if laddr != nil {
		conn.laddr = laddr.Copy()
		regAddr.Port = conn.laddr.L4Port
	} else {
		conn.laddr = &Addr{}
		conn.laddr.Host = addr.HostFromIP(net.IPv4zero)
		conn.laddr.IA = conn.scionNet.localIA
	}
	regAddr.Addr = conn.laddr.Host

	if conn.laddr.IA == nil {
		conn.laddr.IA = n.IA()
	}

	if !conn.laddr.IA.Eq(conn.scionNet.localIA) {
		return nil, common.NewCError("Unable to listen on non-local IA",
			"expected", conn.scionNet.localIA, "actual", conn.laddr.IA, "type", "public")
	}

	if baddr != nil {
		conn.baddr = baddr.Copy()
		bindAddr = &reliable.AppAddr{Addr: conn.baddr.Host, Port: conn.baddr.L4Port}
		if !conn.baddr.IA.Eq(conn.scionNet.localIA) {
			return nil, common.NewCError("Unable to listen on non-local IA", "expected",
				conn.scionNet.localIA, "actual", conn.baddr.IA, "type", "bind")
		}
	}

	rconn, port, err := reliable.Register(conn.scionNet.dispatcherPath,
		conn.laddr.IA, regAddr, bindAddr, svc)
	if err != nil {
		return nil, common.NewCError("Unable to register with dispatcher",
			"err", err)
	}
	log.Info("Registered with dispatcher", "ia", conn.scionNet.localIA, "host", regAddr.Addr,
		"port", port)
	conn.laddr.L4Port = port
	conn.conn = rconn
	return conn, nil
}

// PathResolver returns the pathmgr.PR that the network is using.
func (n *Network) PathResolver() *pathmgr.PR {
	return n.pathResolver
}

// IA returns a copy of the ISD-AS assigned to n
func (n *Network) IA() *addr.ISD_AS {
	return n.localIA.Copy()
}
