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

// Package servers contains the logic for creating and managing SCIOND API
// servers. It currently supports listening on ReliableSocket and UNIX Domain
// socket (in unixgram mode).
package servers

import (
	"bytes"
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

// ConnHandler is a SCIOND API server running on top of a PacketConn. It
// reads messages from the transport, and passes them to the relevant request
// handler.
type ConnHandler struct {
	Conn net.PacketConn
	// State for request Handlers
	Handlers map[proto.SCIONDMsg_Which]Handler
	Logger   log.Logger
}

func NewConnHandler(conn net.PacketConn,
	handlers HandlerMap, logger log.Logger) *ConnHandler {

	return &ConnHandler{
		Conn:     conn,
		Handlers: handlers,
		Logger:   logger,
	}
}

func (srv *ConnHandler) Serve() error {
	for {
		b := make(common.RawBytes, common.MaxMTU)
		n, address, err := srv.Conn.ReadFrom(b)
		if err != nil {
			return err
		}
		go func() {
			defer log.LogPanicAndExit()
			srv.Handle(b[:n], address)
		}()
	}
}

func (srv *ConnHandler) Handle(b common.RawBytes, address net.Addr) {
	p := &sciond.Pld{}
	if err := proto.ParseFromReader(p, bytes.NewReader(b)); err != nil {
		log.Error("capnp error", "err", err)
		return
	}
	handler, ok := srv.Handlers[p.Which]
	if !ok {
		log.Error("handler not found for capnp message", "which", p.Which)
		return
	}
	ctx := log.CtxWith(context.Background(), srv.Logger.New("debug_id", util.GetDebugID()))
	handler.Handle(ctx, srv.Conn, address, p)
}

func (srv *ConnHandler) Close() error {
	return srv.Conn.Close()
}
