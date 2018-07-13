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
	"io"
	"net"
	"sync"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/proto"
)

type HandlerMap map[proto.SCIONDMsg_Which]Handler

// Server listens for new connections on a "unixpacket" or "rsock" network.
// Whenever a new connection is accepted, a SCIOND API server is created to
// handle the connection.
type Server struct {
	network  string
	address  string
	handlers map[proto.SCIONDMsg_Which]Handler
	log      log.Logger
	mu       sync.Mutex // protect access to listener during init/close
	listener net.Listener
}

// NewServer initializes a new server at address on the specified network. The
// server will route requests to their correct handlers based on the
// HandlerMap. To start listening on the address, call ListenAndServe.
//
// Network must be "unixpacket" or "rsock".
func NewServer(network string, address string, handlers HandlerMap, logger log.Logger) *Server {
	return &Server{
		network:  network,
		address:  address,
		handlers: handlers,
		log:      logger,
	}
}

// ListenAndServe starts listening on srv's address, and repeatedly accepts
// connections from clients. For each accepted connection, a SCIONDMsg server
// is started as a separate goroutine; the server will manage the connection
// until it is closed by the client.
func (srv *Server) ListenAndServe() error {
	srv.mu.Lock()
	listener, err := srv.listen()
	if err != nil {
		srv.mu.Unlock()
		return common.NewBasicError("unable to listen on socket", nil,
			"address", srv.address, "err", err)
	}
	srv.listener = listener
	srv.mu.Unlock()

	for {
		conn, err := srv.listener.Accept()
		if err != nil {
			srv.log.Warn("unable to accept conn", "err", err)
			continue
		}

		// Launch transport handler for SCIONDMsg messages on the accepted conn
		go func() {
			defer log.LogPanicAndExit()
			pconn := conn.(net.PacketConn)
			hdl := NewTransportHandler(transport.NewPacketTransport(pconn), srv.handlers, srv.log)
			if err := hdl.Serve(); err != nil && err != io.EOF {
				srv.log.Error("Transport handler error", "err", err)
			}
		}()
	}
}

func (srv *Server) listen() (net.Listener, error) {
	switch srv.network {
	case "unixpacket":
		laddr, err := net.ResolveUnixAddr("unixpacket", srv.address)
		if err != nil {
			return nil, err
		}
		return net.ListenUnix("unixpacket", laddr)
	case "rsock":
		return reliable.Listen(srv.address)
	default:
		return nil, common.NewBasicError("unknown network", nil, "net", srv.network)
	}
}

// Close makes the Server stop listening for new connections, and immediately
// closes all running SCIONDMsg servers that have been launched by this server.
func (srv *Server) Close() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.listener == nil {
		return common.NewBasicError("unitialized server", nil)
	}
	return srv.listener.Close()
	// FIXME(scrye): shut down running servers once we actually implement the
	// handlers.
}

// Shutdown makes the Server stop listening for new connections, and cleanly
// shuts down all running SCIONDMsg servers that have been launched by this
// server.
func (srv *Server) Shutdown(ctx context.Context) error {
	// Ignore context during close as it should rarely block for non-negligible
	// time.
	if err := srv.Close(); err != nil {
		return err
	}

	// FIXME(scrye): cleanly close running SCIONDMsg servers here.
	return nil
}
