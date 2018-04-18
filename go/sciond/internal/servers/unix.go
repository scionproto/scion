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

package servers

import (
	"context"
	"net"
	"sync"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/transport"
)

// UnixSockServer listens for SCIONDMsg capnp messages on a UNIX domain with
// SOCK_DGRAM socket by running a SCIOND API server directly on top of the
// socket.
//
// The zero value for UnixSockServer is a valid configuration.
type UnixSockServer struct {
	Address   string
	Messenger infra.Messenger
	Log       log.Logger

	mu        sync.Mutex // protect access to transport during init/close
	transport infra.Transport
}

// UnixServer starts a SCIONDMSg server on the UNIX SOCK_DGRAM socket at
// address. The server handles SCIOND messages coming from clients, intepreting
// data as raw capnp. Each capnp SCIOND message must be entirely contained in a
// single UNIX datagram. If a datagram contains data after the capnp message,
// the extra data is ignored. Messages received from clients that have not
// bound to a local UNIX address are logged and discarded, as there is no way
// to answer to them (see man 7 unix for more info).
func (srv *UnixSockServer) ListenAndServe() error {
	unixAddr := net.UnixAddr{
		Name: srv.Address,
		Net:  "unixgram",
	}
	conn, err := net.ListenUnixgram("unixgram", &unixAddr)
	if err != nil {
		log.Error("unix listen error", "err", err)
		return nil
	}
	srv.mu.Lock()
	srv.transport = transport.NewPacketTransport(conn)
	srv.mu.Unlock()

	sciondServer := &API{
		Transport: srv.transport,
	}
	return sciondServer.Serve()
}

// Close immediately shuts down the SCIONDMsg server.
func (srv *UnixSockServer) Close() error {
	return srv.closeCtx(context.Background())
}

// closeCtx is the context-aware version of Close.
func (srv *UnixSockServer) closeCtx(ctx context.Context) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.transport == nil {
		return common.NewBasicError("uninitialized UnixSockServer", nil)
	}
	return srv.transport.Close(ctx)
}

// Shutdown cleanly shuts down the SCIONDMsg server.
func (srv *UnixSockServer) Shutdown(ctx context.Context) error {
	if err := srv.closeCtx(ctx); err != nil {
		return err
	}

	// FIXME(scrye): Implement the clean shutdown part
	return nil
}
