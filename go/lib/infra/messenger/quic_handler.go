// Copyright 2019 ETH Zurich
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
	"context"
	"sync"
	"time"

	capnp "zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/rpc"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

var _ rpc.Handler = (*QUICHandler)(nil)

// QUICHandler is a QUIC RPC handler for Messenger messages. Infra handlers can
// be registered for various message types by calling Handle.
type QUICHandler struct {
	handlersLock sync.RWMutex
	handlers     map[infra.MessageType]infra.Handler

	timeout      time.Duration
	parentLogger log.Logger
	parentCtx    context.Context
}

func (h *QUICHandler) ServeRPC(rw rpc.ReplyWriter, request *rpc.Request) {
	signedPld, err := msgToSignedPld(request.Message)
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

	messageType, messageContent, err := validate(pld)
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

	serveCtx, serveCancelF := context.WithTimeout(h.parentCtx, h.timeout)
	defer serveCancelF()

	serveCtx = infra.NewContextWithResponseWriter(serveCtx,
		&QUICResponseWriter{
			ReplyWriter: rw,
			ID:          pld.ReqId,
		},
	)
	serveCtx = log.CtxWith(serveCtx, h.parentLogger.New("debug_id", util.GetDebugID()))

	handler.Handle(infra.NewRequest(serveCtx, messageContent, signedPld,
		request.Address, pld.ReqId))
}

// Handle registers the handler for the given message type.
func (h *QUICHandler) Handle(msgType infra.MessageType, handler infra.Handler) {
	h.handlersLock.Lock()
	h.handlers[msgType] = handler
	h.handlersLock.Unlock()
}

func msgToSignedPld(msg *capnp.Message) (*ctrl.SignedPld, error) {
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

func signedPldToMsg(signedPld *ctrl.SignedPld) (*capnp.Message, error) {
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
