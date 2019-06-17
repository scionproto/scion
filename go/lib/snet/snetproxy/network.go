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
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

var _ reliable.DispatcherService = (*ReconnectingDispatcherService)(nil)

// ReconnectingDispatcherService is a dispatcher wrapper that creates conns
// with transparent reconnection capabilities. Connections created by
// ReconnectingDispatcherService also validate that dispatcher registrations do
// not change addresses.
//
// Callers interested in providing their own reconnection callbacks and
// validating the new connection themselves should use the proxy connection
// constructors directly.
type ReconnectingDispatcherService struct {
	dispatcher reliable.DispatcherService
}

// NewReconnectingDispatcherService adds transparent reconnection capabilities
// to dispatcher connections.
func NewReconnectingDispatcherService(
	dispatcher reliable.DispatcherService) *ReconnectingDispatcherService {

	return &ReconnectingDispatcherService{dispatcher: dispatcher}
}

func (pn *ReconnectingDispatcherService) Register(ia addr.IA, public *addr.AppAddr,
	bind *overlay.OverlayAddr, svc addr.HostSVC) (net.PacketConn, uint16, error) {

	return pn.RegisterTimeout(ia, public, bind, svc, 0)
}

func (pn *ReconnectingDispatcherService) RegisterTimeout(ia addr.IA, public *addr.AppAddr,
	bind *overlay.OverlayAddr, svc addr.HostSVC,
	timeout time.Duration) (net.PacketConn, uint16, error) {

	listener := pn.newReconnecterFromListenArgs(ia, public, bind, svc, timeout)
	conn, port, err := listener.Reconnect(timeout)
	if err != nil {
		return nil, 0, err
	}
	reconnecter := pn.newReconnecterFromListenArgs(ia, public, bind, svc, timeout)
	return NewProxyConn(conn, reconnecter), port, nil
}

func (pn *ReconnectingDispatcherService) newReconnecterFromListenArgs(ia addr.IA,
	public *addr.AppAddr, bind *overlay.OverlayAddr,
	svc addr.HostSVC, timeout time.Duration) *TickingReconnecter {

	f := func(timeout time.Duration) (net.PacketConn, uint16, error) {
		return pn.dispatcher.RegisterTimeout(ia, public, bind, svc, timeout)
	}
	return NewTickingReconnecter(f)
}
