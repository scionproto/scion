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

package reconnect

import (
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

// DispatcherService is a dispatcher wrapper that creates conns
// with transparent reconnection capabilities. Connections created by
// DispatcherService also validate that dispatcher registrations do
// not change addresses.
//
// Callers interested in providing their own reconnection callbacks and
// validating the new connection themselves should use the connection
// constructors directly.
type DispatcherService struct {
	dispatcher reliable.DispatcherService
}

// NewDispatcherService adds transparent reconnection capabilities
// to dispatcher connections.
func NewDispatcherService(
	dispatcher reliable.DispatcherService) *DispatcherService {

	return &DispatcherService{dispatcher: dispatcher}
}

func (pn *DispatcherService) Register(ia addr.IA, public *addr.AppAddr,
	bind *overlay.OverlayAddr, svc addr.HostSVC) (net.PacketConn, uint16, error) {

	return pn.RegisterTimeout(ia, public, bind, svc, 0)
}

func (pn *DispatcherService) RegisterTimeout(ia addr.IA, public *addr.AppAddr,
	bind *overlay.OverlayAddr, svc addr.HostSVC,
	timeout time.Duration) (net.PacketConn, uint16, error) {

	// Perform initial connection to allocate port. We use a reconnecter here
	// to set up the initial connection using the same retry logic we use when
	// losing the connection to the dispatcher.
	reconnecter := pn.newReconnecterFromListenArgs(ia, public, bind, svc, timeout)
	conn, port, err := reconnecter.Reconnect(timeout)
	if err != nil {
		return nil, 0, err
	}
	var newPublic *addr.AppAddr
	if public != nil {
		newPublic = public.Copy()
		newPublic.L4 = addr.NewL4UDPInfo(port)
	}
	reconnecter = pn.newReconnecterFromListenArgs(ia, newPublic, bind, svc, timeout)
	return NewPacketConn(conn, reconnecter), port, nil
}

func (pn *DispatcherService) newReconnecterFromListenArgs(ia addr.IA,
	public *addr.AppAddr, bind *overlay.OverlayAddr,
	svc addr.HostSVC, timeout time.Duration) *TickingReconnecter {

	f := func(timeout time.Duration) (net.PacketConn, uint16, error) {
		return pn.dispatcher.RegisterTimeout(ia, public, bind, svc, timeout)
	}
	return NewTickingReconnecter(f)
}
