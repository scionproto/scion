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
	"sync"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/transport"
	liblog "github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

// RSockServers listens for new RSock connections on a UNIX domain with
// SOCK_STREAM socket. Whenever a new connection is accepted, an SCIOND API
// server is created to handle the connection.
//
// The zero value for RSockServer is a valid configuration.
type RSockServer struct {
	address  string
	msger    infra.Messenger
	log      log.Logger
	mu       sync.Mutex // protect access to listener during init/close
	listener *reliable.Listener
}

func NewRSockServer(address string, msger infra.Messenger, logger log.Logger) *RSockServer {
	return &RSockServer{
		address: address,
		msger:   msger,
		log:     logger,
	}
}

// ListenAndServe listens on the UNIX stream socket at address, and
// repeatedly accepts connections from clients. Stream data is interpreted
// according to the Reliable Socket protocol described in go/lib/sock/reliable.
// For each accepted connection, a SCIONDMsg server is started as a separate
// goroutine; the server will manage the connection until it is closed by the
// client.
func (srv *RSockServer) ListenAndServe() error {
	var err error
	srv.mu.Lock()
	srv.listener, err = reliable.Listen(srv.address)
	srv.mu.Unlock()
	if err != nil {
		return common.NewBasicError("unable to listen on reliable socket", nil,
			"address", srv.address, "err", err)
	}
	for {
		conn, err := srv.listener.Accept()
		if err != nil {
			srv.log.Warn("unable to accept reliable socket conn", "err", err)
		}

		// Launch server for SCIONDMsg messages on the accepted conn
		go func() {
			defer liblog.LogPanicAndExit()
			NewAPI(transport.NewPacketTransport(conn)).Serve()
		}()
	}
}

// Close makes the ReliableSockServer stop listening for new reliable socket
// connections, and immediately closes all running SCIONDMsg servers that have
// been launched by this server.
func (srv *RSockServer) Close() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.listener == nil {
		return common.NewBasicError("unitialized RSockServer", nil)
	}
	return srv.listener.Close()
}

// Shutdown makes the ReliableSockServer stop listening for new reliable socket
// connections, and cleanly shuts down all running SCIONDMsg servers that have
// been launched by this server.
func (srv *RSockServer) Shutdown(ctx context.Context) error {
	// Ignore context during close as it should rarely block for non-negligible
	// time.
	if err := srv.Close(); err != nil {
		return err
	}

	// FIXME(scrye): cleanly close running SCIONDMsg servers here.
	return nil
}
