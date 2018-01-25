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

// Package messenger contains the default implementation for interface
// infra.Messenger. Sent and received messages must be one of the supported
// types below.
//
// The following message types are valid messages. For messages marked (nv), no
// signature verification is performed on the SignedPld.
//  ChainRequest -> ctrl.SignedPld/ctrl.Pld/cert_mgmt.ChainReq (nv)
//  Chain        -> ctrl.SignedPld/ctrl.Pld/cert_mgmt.Chain    (nv)
//  TRCRequest   -> ctrl.SignedPld/ctrl.Pld/cert_mgmt.TRCReq   (nv)
//  TRC          -> ctrl.SignedPld/ctrl.Pld/cert_mgmt.TRC      (nv)
//  PathRequest  -> ctrl.SignedPld/ctrl.Pld/path_mgmt.SegReq   (nv)
//
// Unsupported messages are returned by Messenger.RecvMsg(), but if the
// messages are processed via method ListenAndServe they are logged and
// dropped.
//
// The word "reliable" in method descriptions means a reliable protocol is used
// to deliver that message.
//
// Messages can be received and serviced explicitly via RecvMsg. However,
// Messenger also includes a generic server framework for CtrlPld messages.
//
// To start processing messages received via the Messenger, call
// ListenAndServe. The method runs in the current goroutine, and spawns new
// goroutines to handle each received message:
//  msger := New(...)
//  msger.ListenAndServe()
//
// ListenAndServe will log errors for all received messages. To process
// messages, handlers need to be registered. Handlers allow different
// infrastructure servers to choose which requests they service, and to exploit
// shared functionality. One handler can be registered for each message type,
// identified by its msgType string:
//   msger.AddHandler("ChainRequest", MyCustomHandler)
//   msger.AddHandler("TRCRequest", MyOtherCustomHandler)
//
// Each handler runs indepedently (i.e., without any synchronization) until
// completion. Goroutines inherit a reference to the Messenger via the
// infra.MessengerContextKey context key. This allows handlers to directly send
// network messages.
//
// Some default handlerss are already implemented; for more
// information, see their package documentation:
//   trust.*Store.CertRequestHandler
//   trust.*Store.TRCRequestHandler
//
// Shut down the server and any running handlers using CloseServer():
//  msger.CloseServer()
//
// CloseServer() does not do graceful shutdown (all handlers are canceled
// immediately) and does not close the Messenger itself.
package messenger

import (
	"context"
	"fmt"
	"net"
	"sync"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/proto"
)

const (
	ChainRequest = "ChainRequest"
	Chain        = "Chain"
	TRCRequest   = "TRCRequest"
	TRC          = "TRC"
)

var _ infra.Messenger = (*Messenger)(nil)

// Messenger exposes the API for sending and receiving CtrlPld messages.
type Messenger struct {
	// Networking layer for sending and receiving messages
	dispatcher *disp.Dispatcher
	// Source for crypto objects (certificates and TRCs)
	trustStore *trust.Store

	handlersLock sync.RWMutex
	// Handlers for received messages processing
	handlers map[string]infra.Handler

	lock      sync.Mutex
	closeChan chan struct{}
	// Context passed to blocking receive. Canceled by Close to unblock listeners.
	ctx     context.Context
	cancelF context.CancelFunc

	logger log.Logger
}

// New creates a new Messenger that uses dispatcher for sending and receiving
// messages, and trustStore as crypto information database.
func New(dispatcher *disp.Dispatcher, store *trust.Store, logger log.Logger) *Messenger {
	// XXX(scrye): A trustStore object is passed to the Messenger as it is required
	// to verify top-level signatures. This is never used right now since only
	// unsigned messages are supported. The content of received messages is
	// processed in the relevant handlers which have their own reference to the
	// trustStore.
	ctx, cancelF := context.WithCancel(context.Background())
	return &Messenger{
		dispatcher: dispatcher,
		trustStore: store,
		handlers:   make(map[string]infra.Handler),
		closeChan:  make(chan struct{}),
		ctx:        ctx,
		cancelF:    cancelF,
		logger:     logger,
	}
	// XXX(scrye): More crypto is needed to send signed messages (a local
	// signing key, at a minimum).
}

// RecvMsg reads a new message from the dispatcher. This method is included for
// low-level messaging operations. Applications should instead use method
// ListenAndServe which is a message-type-safe wrapper around RecvMsg.
func (m *Messenger) RecvMsg(ctx context.Context) (proto.Cerealizable, net.Addr, error) {
	return m.dispatcher.RecvFrom(ctx)
}

// GetTRC sends a cert_mgmt.TRCReq request to address a, blocks until it receives a
// reply and returns the reply.
func (m *Messenger) GetTRC(ctx context.Context, msg *cert_mgmt.TRCReq,
	a net.Addr) (*cert_mgmt.TRC, error) {
	signedCtrlPldMsg, err := ctrl.NewSignedCertMgmtPld(msg)
	if err != nil {
		return nil, err
	}
	// Send request and get reply
	replyCtrlPldMsg, err := m.dispatcher.Request(ctx, signedCtrlPldMsg, a)
	if err != nil {
		return nil, err
	}
	_, replyMsg, err := m.validate(replyCtrlPldMsg)
	if err != nil {
		return nil, err
	}
	reply, ok := replyMsg.(*cert_mgmt.TRC)
	if !ok {
		return nil, newTypeAssertErr("*cert_mgmt.TRC", replyMsg)
	}
	return reply, nil
}

// SendTRC sends a reliable cert_mgmt.TRC to address a.
func (m *Messenger) SendTRC(ctx context.Context, msg *cert_mgmt.TRC, a net.Addr) error {
	signedCtrlPldMsg, err := ctrl.NewSignedCertMgmtPld(msg)
	if err != nil {
		return err
	}
	err = m.dispatcher.Notify(ctx, signedCtrlPldMsg, a)
	if err != nil {
		return err
	}
	return nil
}

// GetCertChain sends a cert_mgmt.ChainReq to address a, blocks until it
// receives a reply and returns the reply.
func (m *Messenger) GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq,
	a net.Addr) (*cert_mgmt.Chain, error) {
	signedCtrlPldMsg, err := ctrl.NewSignedCertMgmtPld(msg)
	if err != nil {
		return nil, err
	}
	// Send request and get reply
	replyCtrlPldMsg, err := m.dispatcher.Request(ctx, signedCtrlPldMsg, a)
	if err != nil {
		return nil, err
	}
	_, replyMsg, err := m.validate(replyCtrlPldMsg)
	if err != nil {
		return nil, err
	}
	reply, ok := replyMsg.(*cert_mgmt.Chain)
	if !ok {
		return nil, newTypeAssertErr("*cert_mgmt.Chain", replyMsg)
	}
	return reply, nil
}

// SendCertChain sends a reliable cert_mgmt.Chain to address a.
func (m *Messenger) SendCertChain(ctx context.Context, msg *cert_mgmt.Chain, a net.Addr) error {
	signedCtrlPldMsg, err := ctrl.NewSignedCertMgmtPld(msg)
	if err != nil {
		return err
	}
	err = m.dispatcher.Notify(ctx, signedCtrlPldMsg, a)
	if err != nil {
		return err
	}
	return nil
}

// GetPaths asks the server at the remote address for the paths specified by
// msg, and returns a verified reply.
func (m *Messenger) GetPaths(ctx context.Context, msg *path_mgmt.SegReq,
	a net.Addr) (*path_mgmt.SegReply, error) {
	signedCtrlPldMsg, err := ctrl.NewSignedPathMgmtPld(msg)
	if err != nil {
		return nil, err
	}
	replyCtrlPldMsg, err := m.dispatcher.Request(ctx, signedCtrlPldMsg, a)
	if err != nil {
		return nil, err
	}
	_, replyMsg, err := m.validate(replyCtrlPldMsg)
	if err != nil {
		return nil, err
	}
	reply, ok := replyMsg.(*path_mgmt.SegReply)
	if !ok {
		return nil, newTypeAssertErr("*path_mgmt.SegReply", replyMsg)
	}
	return reply, nil
}

// AddHandler registers a constructor for CtrlPld handlers for msgType.
func (m *Messenger) AddHandler(msgType string, handler infra.Handler) {
	m.handlersLock.Lock()
	m.handlers[msgType] = handler
	m.handlersLock.Unlock()
}

// ListenAndServe starts listening and serving messages on srv's Messenger
// interface. The function runs in the current goroutine. Multiple
// ListenAndServe methods can run in parallel.
func (m *Messenger) ListenAndServe() {
	m.logger.Info("Started listening")
	defer m.logger.Info("Stopped listening")
	for {
		// Recv blocks until a new message is received. To close the server,
		// CloseServer() calls the context's cancel function, thus unblocking Recv. The
		// server's main loop then detects that closeChan has been closed, and shuts
		// down cleanly.
		fmt.Println("waiting for message")
		genericMsg, address, err := m.RecvMsg(m.ctx)
		if err != nil {
			// Do not log errors caused after close signal sent
			select {
			case <-m.closeChan:
				// CloseServer was called
				return
			default:
				m.logger.Error("Receive error", "err", common.FmtError(err))
			}
			continue
		}
		m.serve(genericMsg, address)
	}
}

func (m *Messenger) serve(genericMsg proto.Cerealizable, address net.Addr) {
	// Validate that the message is of acceptable type, and that its top-level
	// signature is correct.
	msgType, msg, err := m.validate(genericMsg)
	if err != nil {
		m.logger.Error("Received message, but unable to validate message", "err",
			common.FmtError(err))
		return
	}

	m.handlersLock.RLock()
	handler := m.handlers[msgType]
	m.handlersLock.RUnlock()
	if handler == nil {
		m.logger.Error("Received message, but handler not found", "msgType", msgType)
		return
	}
	serveCtx := context.WithValue(m.ctx, infra.MessengerContextKey, m)
	// XXX(scrye): The handler might perform additional verifications; for
	// example, a PCB handler will probably verify additional signatures.
	go handler.Handle(serveCtx, msg, genericMsg, address)
}

// validate checks that msg is one of the acceptable message types for SCION
// infra communication (listed in package level documentation), and returns the
// message type ID string, the object containing only the payload, and an error
// (if one occurred).
func (m *Messenger) validate(msg proto.Cerealizable) (string, proto.Cerealizable, error) {
	signedCtrlPld, ok := msg.(*ctrl.SignedPld)
	if !ok {
		return "", nil, common.NewBasicError("Unexpected capnp type", nil, "expected",
			"ctrl.SignedPld", "actual", common.TypeOf(msg))
	}

	// XXX(scrye): For now, only the messages in the top comment of this
	// package are supported. None of them use have a signature at the top, so
	// we can directly extract the payload to discover the unique message type.
	ctrlPld, err := signedCtrlPld.Pld()
	if err != nil {
		return "", nil, common.NewBasicError("Unable to extract CtrlPld from SignedPld", err)
	}

	switch ctrlPld.Which {
	case proto.CtrlPld_Which_certMgmt:
		switch ctrlPld.CertMgmt.Which {
		case proto.CertMgmt_Which_certChainReq:
			return ChainRequest, ctrlPld.CertMgmt.ChainReq, nil
		case proto.CertMgmt_Which_certChain:
			return Chain, ctrlPld.CertMgmt.ChainRep, nil
		case proto.CertMgmt_Which_trcReq:
			return TRCRequest, ctrlPld.CertMgmt.TRCReq, nil
		case proto.CertMgmt_Which_trc:
			return TRC, ctrlPld.CertMgmt.TRCRep, nil
		default:
			return "", nil,
				common.NewBasicError("Unsupported SignedPld.CtrlPld.CertMgmt.Xxx message type", nil)
		}
	default:
		return "", nil, common.NewBasicError("Unsupported SignedPld.Pld.Xxx message type", nil)
	}
}

// CloseServer stops any running ListenAndServe functions, and cancels all running
// handlers. The server's Messenger layer is not closed.
func (m *Messenger) CloseServer() error {
	// Protect against concurrent Close calls
	m.lock.Lock()
	defer m.lock.Unlock()
	select {
	case <-m.closeChan:
		// Already closed, so do nothing
	default:
		close(m.closeChan)
		m.cancelF()
	}
	return nil
}

func newTypeAssertErr(typeStr string, msg interface{}) error {
	errStr := fmt.Sprintf("Unable to type assert disp.Message to %s", typeStr)
	return common.NewBasicError(errStr, nil, "msg", msg)
}
