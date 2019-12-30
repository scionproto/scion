// Copyright 2018 ETH Zurich
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

package reconnect

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect/internal/metrics"
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
	dispatcher reliable.Dispatcher
}

// NewDispatcherService adds transparent reconnection capabilities
// to dispatcher connections.
func NewDispatcherService(dispatcher reliable.Dispatcher) *DispatcherService {
	return &DispatcherService{dispatcher: dispatcher}
}

func (pn *DispatcherService) Register(ctx context.Context, ia addr.IA, public *net.UDPAddr,
	svc addr.HostSVC) (net.PacketConn, uint16, error) {

	// Perform initial connection to allocate port. We use a reconnecter here
	// to set up the initial connection using the same retry logic we use when
	// losing the connection to the dispatcher.
	reconnecter := pn.newReconnecterFromListenArgs(ctx, ia, public, svc)
	conn, port, err := reconnecter.Reconnect(ctx)
	if err != nil {
		return nil, 0, err
	}

	updatePort := func(a *net.UDPAddr, port int) *net.UDPAddr {
		if a == nil {
			return nil
		}
		return &net.UDPAddr{
			IP:   append(a.IP[:0:0], a.IP...),
			Port: port,
		}
	}
	newPublic := updatePort(public, int(port))
	reconnecter = pn.newReconnecterFromListenArgs(ctx, ia, newPublic, svc)
	return NewPacketConn(conn, reconnecter), port, nil
}

func (pn *DispatcherService) newReconnecterFromListenArgs(ctx context.Context, ia addr.IA,
	public *net.UDPAddr, svc addr.HostSVC) *TickingReconnecter {

	// f represents individual connection attempts
	f := func(timeout time.Duration) (net.PacketConn, uint16, error) {
		metrics.M.Retries().Inc()
		ctx := context.Background()
		if timeout != 0 {
			var cancelF context.CancelFunc
			ctx, cancelF = context.WithTimeout(ctx, timeout)
			defer cancelF()
		}
		conn, port, err := pn.dispatcher.Register(ctx, ia, public, svc)
		if errors.Is(err, ErrReconnecterTimeoutExpired) {
			metrics.M.Timeouts().Inc()
		}
		return conn, port, err
	}
	return NewTickingReconnecter(f)
}
