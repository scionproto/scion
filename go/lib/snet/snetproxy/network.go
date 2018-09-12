// Copyright 2018 ETH Zurich
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

package snetproxy

import (
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

var _ snet.Network = (*ProxyNetwork)(nil)

// ProxyNetwork is a wrapper network that creates conns with transparent
// reconnection capabilities. Connections created by ProxyNetwork also validate
// that dispatcher registrations do not change addresses.
//
// Callers interested in providing their own reconnection callbacks and
// validating the new connection themselves should use the proxy connection
// constructors directly.
type ProxyNetwork struct {
	network snet.Network
}

// NewProxyNetwork adds transparent reconnection capabilities to the
// connections created by an snet network.
func NewProxyNetwork(network snet.Network) *ProxyNetwork {
	return &ProxyNetwork{network: network}
}

func (pn *ProxyNetwork) DialSCIONWithBindSVC(network string,
	laddr, raddr, baddr *snet.Addr, svc addr.HostSVC, timeout time.Duration) (snet.Conn, error) {

	dialer := pn.newReconnecterFromDialArgs(network, laddr, raddr, baddr, svc)
	conn, err := dialer.Reconnect(timeout)
	if err != nil {
		return nil, err
	}
	reconnecter := pn.newReconnecterFromDialArgs(
		network,
		toSnetAddr(conn.LocalAddr()),
		toSnetAddr(conn.RemoteAddr()),
		toSnetAddr(conn.BindAddr()),
		conn.SVC(),
	)
	return NewProxyConn(conn, reconnecter), nil
}

func (pn *ProxyNetwork) newReconnecterFromDialArgs(network string, laddr, raddr, baddr *snet.Addr,
	svc addr.HostSVC) *TickingReconnecter {

	f := func(timeout time.Duration) (snet.Conn, error) {
		return pn.network.DialSCIONWithBindSVC(network, laddr, raddr, baddr, svc, timeout)
	}
	return NewTickingReconnecter(f)
}

func (pn *ProxyNetwork) ListenSCIONWithBindSVC(network string,
	laddr, baddr *snet.Addr, svc addr.HostSVC, timeout time.Duration) (snet.Conn, error) {

	listener := pn.newReconnecterFromListenArgs(network, laddr, baddr, svc)
	conn, err := listener.Reconnect(timeout)
	if err != nil {
		return nil, err
	}
	reconnecter := pn.newReconnecterFromListenArgs(
		network,
		toSnetAddr(conn.LocalAddr()),
		toSnetAddr(conn.BindAddr()),
		conn.SVC(),
	)
	return NewProxyConn(conn, reconnecter), nil
}

func (pn *ProxyNetwork) newReconnecterFromListenArgs(network string,
	laddr, baddr *snet.Addr, svc addr.HostSVC) *TickingReconnecter {

	f := func(timeout time.Duration) (snet.Conn, error) {
		return pn.network.ListenSCIONWithBindSVC(network, laddr, baddr, svc, timeout)
	}
	return NewTickingReconnecter(f)
}

func toSnetAddr(address net.Addr) *snet.Addr {
	if address == nil {
		return nil
	}
	return address.(*snet.Addr)
}
