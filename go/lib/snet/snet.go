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
// to shutdown the socket (see https://github.com/scionproto/scion/pull/1356).
// To prevent this on a Conn object with only Write calls, run a separate
// goroutine that continuously calls Read on the Conn.
package snet

import (
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

var (
	// Default SCION networking context for package-level Dial and Listen
	DefNetwork *Network
)

// Init initializes the default SCION networking context.
func Init(ia addr.IA, sciondPath string, dispatcherPath string) error {
	network, err := NewNetwork(ia, sciondPath, dispatcherPath)
	if err != nil {
		return err
	}
	return InitWithNetwork(network)
}

// InitWithNetwork initializes snet with the provided SCION networking context.
func InitWithNetwork(network *Network) error {
	if DefNetwork != nil {
		return common.NewBasicError("Cannot initialize global SCION network twice", nil)
	}
	DefNetwork = network
	return nil
}

// IA returns the default ISD-AS
func IA() addr.IA {
	if DefNetwork == nil {
		return addr.IA{}
	}
	return DefNetwork.localIA
}

// SCION networking context, containing local ISD-AS, SCIOND, Dispatcher and
// Path resolver.
type Network struct {
	dispatcherPath string
	// pathResolver references the default source of paths for a Network. This
	// is set to nil when operating on a SCIOND-less Network.
	pathResolver *pathmgr.PR
	localIA      addr.IA
}

// NewNetworkWithPR creates a new networking context with path resolver pr. A
// nil path resolver means the Network will run without SCIOND.
func NewNetworkWithPR(ia addr.IA, dispatcherPath string, pr *pathmgr.PR) *Network {
	if dispatcherPath == "" {
		dispatcherPath = reliable.DefaultDispPath
	}
	return &Network{
		dispatcherPath: dispatcherPath,
		pathResolver:   pr,
		localIA:        ia,
	}
}

// NewNetwork creates a new networking context, on which future Dial or Listen
// calls can be made. The new connections use the SCIOND server at sciondPath,
// the dispatcher at dispatcherPath, and ia for the local ISD-AS.
//
// If sciondPath is the empty string, the network will run without SCIOND. In
// this mode of operation, the app is fully responsible with supplying paths
// for sent traffic.
func NewNetwork(ia addr.IA, sciondPath string, dispatcherPath string) (*Network, error) {
	var pathResolver *pathmgr.PR
	if sciondPath != "" {
		var err error
		pathResolver, err = pathmgr.New(
			sciond.NewService(sciondPath),
			&pathmgr.Timers{
				NormalRefire: time.Minute,
				ErrorRefire:  3 * time.Second,
				MaxAge:       time.Hour,
			},
			log.Root(),
		)
		if err != nil {
			return nil, common.NewBasicError("Unable to initialize path resolver", err)
		}
	}
	return NewNetworkWithPR(ia, dispatcherPath, pathResolver), nil
}

// DialSCION returns a SCION connection to raddr. Nil values for laddr are not
// supported yet.  Parameter network must be "udp4". The returned connection's
// Read and Write methods can be used to receive and send SCION packets.
//
// A negative timeout means infinite timeout.
func (n *Network) DialSCION(network string, laddr, raddr *Addr,
	timeout time.Duration) (*Conn, error) {

	return n.DialSCIONWithBindSVC(network, laddr, raddr, nil, addr.SvcNone, timeout)
}

// DialSCIONWithBindSVC returns a SCION connection to raddr. Nil values for laddr are not
// supported yet.  Parameter network must be "udp4". The returned connection's
// Read and Write methods can be used to receive and send SCION packets.
//
// A negative timeout means infinite timeout.
func (n *Network) DialSCIONWithBindSVC(network string, laddr, raddr, baddr *Addr,
	svc addr.HostSVC, timeout time.Duration) (*Conn, error) {

	if raddr == nil {
		return nil, common.NewBasicError("Unable to dial to nil remote", nil)
	}
	conn, err := n.ListenSCIONWithBindSVC(network, laddr, baddr, svc, timeout)
	if err != nil {
		return nil, err
	}
	conn.raddr = raddr.Copy()
	if n.pathResolver != nil {
		conn.sp, err = n.pathResolver.Watch(conn.laddr.IA, conn.raddr.IA)
		if err != nil {
			return nil, common.NewBasicError("Unable to establish path", err)
		}
	}
	return conn, nil
}

// ListenSCION registers laddr with the dispatcher. Nil values for laddr are
// not supported yet. The returned connection's ReadFrom and WriteTo methods
// can be used to receive and send SCION packets with per-packet addressing.
// Parameter network must be "udp4".
//
// A negative timeout means infinite timeout.
func (n *Network) ListenSCION(network string, laddr *Addr, timeout time.Duration) (*Conn, error) {
	return n.ListenSCIONWithBindSVC(network, laddr, nil, addr.SvcNone, timeout)
}

// ListenSCIONWithBindSVC registers laddr with the dispatcher. Nil values for laddr are
// not supported yet. The returned connection's ReadFrom and WriteTo methods
// can be used to receive and send SCION packets with per-packet addressing.
// Parameter network must be "udp4".
//
// A negative timeout means infinite timeout.
func (n *Network) ListenSCIONWithBindSVC(network string, laddr, baddr *Addr,
	svc addr.HostSVC, timeout time.Duration) (*Conn, error) {
	if network != "udp4" {
		return nil, common.NewBasicError("Network not implemented", nil, "net", network)
	}
	// FIXME(scrye): If no local address is specified, we want to
	// bind to the address of the outbound interface on a random
	// free port. However, the current dispatcher version cannot
	// expose that address. Additionally, the dispatcher does not follow
	// normal operating system semantics for binding on 0.0.0.0 (it
	// considers it to be a fixed address instead of a wildcard). To avoid
	// misuse, disallow binding to nil or 0.0.0.0 addresses for now.
	if laddr == nil {
		return nil, common.NewBasicError("Nil laddr not supported", nil)
	}
	if laddr.Host == nil {
		return nil, common.NewBasicError("Nil Host laddr not supported", nil)
	}
	if laddr.Host.L3 == nil {
		return nil, common.NewBasicError("Nil Host L3 laddr not supported", nil)
	}
	if laddr.Host.L4 == nil {
		// If no port has been specified, default to 0 to get a random port from the dispatcher
		laddr.Host.L4 = addr.NewL4UDPInfo(0)
	}
	if laddr.Host.L3.Type() != addr.HostTypeIPv4 || laddr.Host.L4.Type() != common.L4UDP {
		return nil, common.NewBasicError("Supplied local address does not match network", nil,
			"expected L3", addr.HostTypeIPv4, "actual L3", laddr.Host.L3.Type(),
			"expected L4", common.L4UDP, "actual L4", laddr.Host.L4.Type())
	}
	if laddr.Host.L3.IP().Equal(net.IPv4zero) {
		return nil, common.NewBasicError("Binding to 0.0.0.0 not supported", nil)
	}
	conn := &Conn{
		net:        network,
		scionNet:   n,
		recvBuffer: make(common.RawBytes, BufSize),
		sendBuffer: make(common.RawBytes, BufSize),
		svc:        svc}
	// Initialize local bind address
	// NOTE: keep nil address logic for now, even though we do not support it yet
	if laddr != nil {
		conn.laddr = laddr.Copy()
	} else {
		l4 := addr.NewL4UDPInfo(0)
		conn.laddr = &Addr{}
		conn.laddr.Host = &addr.AppAddr{L3: addr.HostIPv4(net.IPv4zero), L4: l4}
		conn.laddr.IA = conn.scionNet.localIA
	}
	if conn.laddr.IA.IsZero() {
		conn.laddr.IA = n.IA()
	}
	if !conn.laddr.IA.Eq(conn.scionNet.localIA) {
		return nil, common.NewBasicError("Unable to listen on non-local IA", nil,
			"expected", conn.scionNet.localIA, "actual", conn.laddr.IA, "type", "public")
	}
	var bindAddr *addr.AppAddr
	if baddr != nil {
		conn.baddr = baddr.Copy()
		bindAddr = baddr.Host
		if !conn.baddr.IA.Eq(conn.scionNet.localIA) {
			return nil, common.NewBasicError("Unable to listen on non-local IA", nil,
				"expected", conn.scionNet.localIA, "actual", conn.baddr.IA, "type", "bind")
		}
	}
	rconn, port, err := reliable.RegisterTimeout(conn.scionNet.dispatcherPath,
		conn.laddr.IA, conn.laddr.Host, bindAddr, svc, timeout)
	if err != nil {
		return nil, common.NewBasicError("Unable to register with dispatcher", err)
	}
	if port != conn.laddr.Host.L4.Port() {
		// Update port
		conn.laddr.Host.L4 = addr.NewL4UDPInfo(port)
	}
	log.Info("Registered with dispatcher", "addr", conn.laddr)
	conn.conn = rconn
	return conn, nil
}

// PathResolver returns the pathmgr.PR that the network is using.
func (n *Network) PathResolver() *pathmgr.PR {
	return n.pathResolver
}

// Sciond returns the sciond.Service that the network is using.
func (n *Network) Sciond() sciond.Service {
	if n.pathResolver != nil {
		return n.pathResolver.Sciond()
	}
	return nil
}

// IA returns the ISD-AS assigned to n
func (n *Network) IA() addr.IA {
	return n.localIA
}
