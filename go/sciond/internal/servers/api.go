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

// Package servers contains the logic for creating and managing SCIOND API
// servers. It currently supports listening on ReliableSocket and UNIX Domain
// socket (in unixgram mode).
package servers

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"github.com/opentracing/opentracing-go"
	opentracingext "github.com/opentracing/opentracing-go/ext"
	capnp "zombiezen.com/go/capnproto2"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/proto"
)

// ConnHandler is a SCIOND API server running on top of a PacketConn. It
// reads messages from the transport, and passes them to the relevant request
// handler.
type ConnHandler struct {
	Conn net.Conn
	// State for request Handlers
	Handlers map[proto.SCIONDMsg_Which]Handler
}

func (srv *ConnHandler) Serve(address net.Addr) {
	msg, err := proto.SafeDecode(capnp.NewDecoder(srv.Conn))
	if err != nil {
		log.Error("Unable to decode RPC request", "err", err)
		return
	}

	root, err := msg.RootPtr()
	if err != nil {
		log.Error("Unable to extract capnp root", "err", err)
		return
	}

	p := &sciond.Pld{}
	if err := proto.SafeExtract(p, proto.SCIONDMsg_TypeID, root.Struct()); err != nil {
		log.Error("Unable to extract capnp SCIOND payload", "err", err)
		return
	}

	handler, ok := srv.Handlers[p.Which]
	if !ok {
		log.Error("handler not found for capnp message", "which", p.Which)
		return
	}

	var spanCtx opentracing.SpanContext
	if len(p.TraceId) > 0 {
		var err error
		spanCtx, err = opentracing.GlobalTracer().Extract(opentracing.Binary,
			bytes.NewReader(p.TraceId))
		if err != nil {
			log.Error("Failed to extract span", "err", err)
		}
	}

	span, ctx := tracing.CtxWith(context.Background(), fmt.Sprintf("%s.handler", p.Which),
		opentracingext.RPCServerOption(spanCtx))
	defer span.Finish()

	handler.Handle(ctx, srv.Conn, address, p)
}

func (srv *ConnHandler) Close() error {
	return srv.Conn.Close()
}
