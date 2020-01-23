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

package messenger

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	opentracingext "github.com/opentracing/opentracing-go/ext"
	capnp "zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/rpc"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/proto"
)

var _ rpc.Handler = (*QUICHandler)(nil)

// NewStreamHandler creates a RPC handler for Messenger messages. Infra handlers
// can be registered for various message types by calling Handle.
func NewStreamHandler(parentCtx context.Context, timeout time.Duration) *QUICHandler {
	return &QUICHandler{
		handlers:  make(map[infra.MessageType]infra.Handler),
		timeout:   timeout,
		parentCtx: parentCtx,
	}
}

// QUICHandler is a QUIC RPC handler for Messenger messages. Infra handlers can
// be registered for various message types by calling Handle.
type QUICHandler struct {
	handlersLock sync.RWMutex
	handlers     map[infra.MessageType]infra.Handler

	timeout   time.Duration
	parentCtx context.Context
}

func (h *QUICHandler) ServeRPC(rw rpc.ReplyWriter, request *rpc.Request) {
	signedPld, err := MsgToSignedPld(request.Message)
	if err != nil {
		log.Error("Unable to extract SignedPld from capnp", "from", request.Address, "err", err)
		return
	}

	pld, err := signedPld.UnsafePld()
	if err != nil {
		// TODO(scrye): Right now we only log this because the UDP code behaved
		// this way.  However, in the future we can also inform the remote end
		// that their message was invalid.
		log.Error("Unable to extract Pld from CtrlPld", "from", request.Address, "err", err)
		return
	}

	messageType, messageContent, err := Validate(pld)
	if err != nil {
		// TODO(scrye): Right now we only log this because the UDP code behaved
		// this way.  However, in the future we can also inform the remote end
		// that their message was invalid.
		log.Error("Received message, but unable to validate message",
			"from", request.Address, "err", err)
		return
	}

	h.handlersLock.RLock()
	handler := h.handlers[messageType]
	h.handlersLock.RUnlock()

	serveCtx, servceCancelF, span := h.prepareServeCtx(pld, messageType, rw)
	defer servceCancelF()
	defer span.Finish()

	if handler == nil {
		log.Error("Message type not handled", "type", messageType)
	} else {
		handler.Handle(infra.NewRequest(serveCtx, messageContent, signedPld,
			request.Address, pld.ReqId))
	}
}

// Handle registers the handler for the given message type.
func (h *QUICHandler) Handle(msgType infra.MessageType, handler infra.Handler) {
	h.handlersLock.Lock()
	h.handlers[msgType] = handler
	h.handlersLock.Unlock()
}

func (h *QUICHandler) prepareServeCtx(pld *ctrl.Pld, messageType infra.MessageType,
	rw rpc.ReplyWriter) (context.Context, context.CancelFunc, opentracing.Span) {

	serveCtx, serveCancelF := context.WithTimeout(h.parentCtx, h.timeout)

	serveCtx = infra.NewContextWithResponseWriter(serveCtx,
		&QUICResponseWriter{
			ReplyWriter: rw,
			ID:          pld.ReqId,
		},
	)

	// Tracing
	var spanCtx opentracing.SpanContext
	if len(pld.Data.TraceId) > 0 {
		var err error
		spanCtx, err = opentracing.GlobalTracer().Extract(opentracing.Binary,
			bytes.NewReader(pld.Data.TraceId))
		if err != nil {
			log.Error("Failed to extract span", "err", err)
		}
	}

	span, ctx := tracing.CtxWith(serveCtx, fmt.Sprintf("%s-handler", messageType),
		opentracingext.RPCServerOption(spanCtx))
	return ctx, serveCancelF, span
}

func MsgToSignedPld(msg *capnp.Message) (*ctrl.SignedPld, error) {
	root, err := msg.RootPtr()
	if err != nil {
		return nil, err
	}
	signedPld := &ctrl.SignedPld{}
	if err := proto.SafeExtract(signedPld, proto.SignedCtrlPld_TypeID, root.Struct()); err != nil {
		return nil, err
	}
	return signedPld, nil
}

func SignedPldToMsg(signedPld *ctrl.SignedPld) (*capnp.Message, error) {
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, err
	}
	root, err := proto.NewRootSignedCtrlPld(seg)
	if err != nil {
		return nil, err
	}
	if err := pogs.Insert(proto.SignedCtrlPld_TypeID, root.Struct, signedPld); err != nil {
		return nil, err
	}
	return msg, nil
}
