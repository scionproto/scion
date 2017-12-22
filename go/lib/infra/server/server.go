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

// Package server contains a generic server framework for CtrlPld messages.
//
// A server runs on top of a *infra.Messenger:
//  messenger := api.New(...)
//  server := New(messenger, log.Root())
//
// To start processing messages received via the Messenger, call
// ListenAndServe. The method runs in the current goroutine, and spawns new
// goroutines to handle each received message:
//  server.ListenAndServe()
//
// A newly created server will throw errors for all received messages. To
// process messages, handlers need to be registered. One handler can be
// registered for each message type, identified by its capnp Proto ID:
//  server.AddHandler(proto.TRCReq_TypeID, MyCustomHandlerConstructor)
//  server.AddHandler(proto.CertChainReq_TypeID, MyOtherCustomHandlerConstructor)
//
// MyCustomHandlerConstructor initializes the state required to service a
// message of the specified type, and then starts a goroutine on top of that
// state. The goroutine runs indepedently (i.e., without any synchronization)
// until completion. Goroutines inherit the Messenger of the server via an
// api.MessengerContextKey context key. This allows handlers to directly send
// network messages.
//
// The following protocols will be supported (with exceptions in parentheses):
// CtrlPld (except base CertMgmt and PathMgmt), CertMgmt, and PathMgmt.
//
// Some default handler constructors are already implemented; for more
// information, see their package documentation:
//   trust.*Cache.NewCertHandler
//   trust.*Cache.NewTRCHandler
//
// Shut down the server and any running handlers using Close():
//   srv.Close()
// Close() does not do graceful shutdown (all handlers are canceled
// immediately) and does not close the server's Messenger.
package server

import (
	"context"
	"net"
	"sync"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/api"
	"github.com/scionproto/scion/go/proto"
)

// Constructs a handler for message msg. Handle() can be called on the
// resulting object to process the message.
type HandlerConstructor func(msg interface{}, peer net.Addr) infra.Handler

type Server struct {
	messenger    *api.Messenger
	constructors map[proto.ProtoIdType]HandlerConstructor

	lock   sync.Mutex
	closeC chan struct{}

	// Context passed to blocking receive. Canceled by Close to unblock listener.
	ctx     context.Context
	cancelF context.CancelFunc

	logger log.Logger
}

// New creates a new server. Argument messenger is used by ListenAndServe to
// receive messages, and by handler goroutines to possibly send messages.
func New(messenger *api.Messenger, logger log.Logger) *Server {
	ctx, cancelF := context.WithCancel(context.Background())
	return &Server{
		messenger:    messenger,
		constructors: make(map[proto.ProtoIdType]HandlerConstructor),
		closeC:       make(chan struct{}),
		ctx:          ctx,
		cancelF:      cancelF,
		logger:       logger,
	}
}

// AddHandler registers a constructor for CtlrPld handlers for msgType.
func (srv *Server) AddHandler(msgType proto.ProtoIdType, f HandlerConstructor) {
	srv.constructors[msgType] = f
}

// ListenAndServe starts listening and serving messages on srv's Messenger
// interface. The function runs in the current goroutine. Multiple
// ListenAndServe methods can run in parallel.
func (srv *Server) ListenAndServe() {
	srv.logger.Info("Started listening")
	defer srv.logger.Info("Stopped listening")
	for {
		select {
		case <-srv.closeC:
			return
		default:
		}
		srv.serve()
	}
}

func (srv *Server) serve() {
	// Recv blocks until a new message is received. To close the server,
	// Close() calls the context's cancel function, thus unblocking Recv. The
	// server's main loop then detects that closeC has been closed, and shuts
	// down cleanly.
	genericMsg, address, err := srv.messenger.RecvMsg(srv.ctx)
	if err != nil {
		// Do not log errors caused after close signal sent
		select {
		case <-srv.closeC:
		default:
			srv.logger.Error("Receive error", "err", err)
		}
		return
	}

	// We only handle capnp messages
	msg, ok := genericMsg.(proto.Cerealizable)
	if !ok {
		srv.logger.Warn("Discarding non-capnp message", "msg", msg)
		return
	}

	constructor := srv.constructors[msg.ProtoId()]
	if constructor == nil {
		srv.logger.Warn("Received message, but handler constructor not found", "protoId", msg.ProtoId())
		return
	}
	handler := constructor(msg, address)
	serveCtx := context.WithValue(srv.ctx, api.MessengerContextKey, srv.messenger)
	go handler.Handle(serveCtx)
}

// Close stops any running ListenAndServe functions, and cancels all running
// handlers. The server's Messenger layer is not closed.
func (srv *Server) Close() error {
	// Protect against concurrent Close calls
	srv.lock.Lock()
	defer srv.lock.Unlock()
	select {
	case <-srv.closeC:
		// Already closed, so do nothing
	default:
		close(srv.closeC)
		srv.cancelF()
	}
	return nil
}
