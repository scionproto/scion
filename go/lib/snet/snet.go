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
package snet

import (
	"net"
	"time"

	log "github.com/inconshreveable/log15"
	cache "github.com/patrickmn/go-cache"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/pathmgr"
	"github.com/netsec-ethz/scion/go/lib/sock/reliable"
)

var (
	// Default SCION networking context for package-level Dial and Listen
	pkgNetwork *Network
)

// Init initializes the default SCION networking context.
func Init(ia *addr.ISD_AS, sPath string, dPath string) error {
	if pkgNetwork != nil {
		return common.NewError("Cannot initialize global SCION network twice")
	}

	network, err := NewNetwork(ia, sPath, dPath)
	if err != nil {
		return err
	}
	pkgNetwork = network
	return nil
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
		localIA:        ia}
	pathResolver, err := pathmgr.New(sPath, time.Minute, log.Root())
	if err != nil {
		return nil, common.NewError("Unable to initialize path resolver", "err", err)
	}
	network.pathResolver = pathResolver
	return network, nil
}

// DialSCION serves the same function as its package-level counterpart, except
// it uses the SCION networking context in n.
func (n *Network) DialSCION(network string, laddr, raddr *Addr) (*Conn, error) {
	conn, err := n.ListenSCION(network, laddr)
	if err != nil {
		return nil, err
	}

	if raddr == nil {
		return nil, common.NewError("Unable to dial to nil remote")
	}

	conn.raddr = raddr.Copy()
	return conn, nil
}

// ListenSCION sservers the same function as its package-level counterpart,
// except it uses the SCION networking context in n.
func (n *Network) ListenSCION(network string, laddr *Addr) (*Conn, error) {
	if pkgNetwork == nil {
		return nil, common.NewError("SCION network not initialized")
	}
	if network != "udp4" {
		return nil, common.NewError("Network not implemented", "net", network)
	}

	conn := &Conn{}
	conn.net = network
	conn.scionNet = n
	conn.pathMap = cache.New(pathTTL, pathCleanupInterval)
	conn.recvBuffer = make(common.RawBytes, BufSize)
	conn.sendBuffer = make(common.RawBytes, BufSize)

	// Initialize local bind address
	var regAddr reliable.AppAddr
	if laddr != nil {
		conn.laddr = laddr.Copy()
		regAddr.Addr = conn.laddr.Host
		regAddr.Port = conn.laddr.Port
	} else {
		conn.laddr = &Addr{}
		conn.laddr.Host = addr.HostFromIP(net.IPv4zero)
		conn.laddr.IA = conn.scionNet.localIA
		regAddr.Addr = conn.laddr.Host
	}

	if !conn.laddr.IA.Eq(conn.scionNet.localIA) {
		return nil, common.NewError("Unable to listen on non-local IA",
			"expected", conn.scionNet.localIA, "actual", conn.laddr.IA)
	}

	rconn, port, err := reliable.Register(conn.scionNet.dispatcherPath,
		conn.scionNet.localIA, regAddr)
	if err != nil {
		return nil, common.NewError("Unable to register with dispatcher",
			"err", err)
	}
	log.Info("Registered with dispatcher", "ia", conn.scionNet.localIA, "host", regAddr.Addr,
		"port", port)
	conn.laddr.Port = port
	conn.conn = rconn
	return conn, nil
}
