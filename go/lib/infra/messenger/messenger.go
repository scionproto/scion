// Copyright 2018 ETH Zurich, Anapaya Systems
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
// types below:
//  infra.ChainRequest        -> ctrl.SignedPld/ctrl.Pld/cert_mgmt.ChainReq
//  infra.Chain               -> ctrl.SignedPld/ctrl.Pld/cert_mgmt.Chain
//  infra.TRCRequest          -> ctrl.SignedPld/ctrl.Pld/cert_mgmt.TRCReq
//  infra.TRC                 -> ctrl.SignedPld/ctrl.Pld/cert_mgmt.TRC
//  infra.IfStateInfos        -> ctrl.SignedPld/ctrl.Pld/path_mgmt.IFStateInfos
//  infra.SegChangesReq       -> ctrl.SignedPld/ctrl.Pld/path_mgmt.SegChangesReq
//  infra.SegChangesReply     -> ctrl.SignedPld/ctrl.Pld/path_mgmt.SegChangesReply
//  infra.SegChangesIdReq     -> ctrl.SignedPld/ctrl.Pld/path_mgmt.SegChangesIdReq
//  infra.SegChangesIdReply   -> ctrl.SignedPld/ctrl.Pld/path_mgmt.SegChangesIdReply
//  infra.SegReq              -> ctrl.SignedPld/ctrl.Pld/path_mgmt.SegReg
//  infra.SegRequest          -> ctrl.SignedPld/ctrl.Pld/path_mgmt.SegReq
//  infra.SegReply            -> ctrl.SignedPld/ctrl.Pld/path_mgmt.SegReply
//  infra.SegRev              -> ctrl.SignedPld/ctrl.Pld/path_mgmt.SRevInfo
//  infra.SegSync             -> ctrl.SignedPld/ctrl.Pld/path_mgmt.SegSync
//  infra.ChainIssueRequest   -> ctrl.SignedPld/ctrl.Pld/cert_mgmt.ChainIssReq
//  infra.ChainIssueReply     -> ctrl.SignedPld/ctrl.Pld/cert_mgmt.ChainIssRep
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
//   msger.AddHandler(infra.ChainRequest, MyCustomHandler)
//   msger.AddHandler(infra.TRCRequest, MyOtherCustomHandler)
//
// Each handler runs indepedently (i.e., without any synchronization) until
// completion. Goroutines inherit a reference to the Messenger via the
// infra.MessengerContextKey context key. This allows handlers to directly send
// network messages.
//
// Some default handlers are already implemented; for more
// information, see their package documentation:
//   trust.*Store.NewChainReqHandler
//   trust.*Store.NewTRCReqHandler
//   trust.*Store.NewChainPushHandler
//   trust.*Store.NewTRCPushHandler
//
// Shut down the server and any running handlers using CloseServer():
//  msger.CloseServer()
//
// CloseServer() does not do graceful shutdown of the handlers and does not
// close the Messenger itself.
package messenger

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/ctrl_msg"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

const (
	DefaultHandlerTimeout = 10 * time.Second
)

// Config can be used to customize the behavior of the Messenger.
type Config struct {
	// HandlerTimeout is the amount of time allocated to the processing of a
	// received message. This includes the time needed to verify the signature
	// and the execution of a registered handler (if one exists). If the
	// timeout is 0, the default is used.
	HandlerTimeout time.Duration
	// DisableSignatureVerification can be set to true to disable the
	// verification of the top level signature in received signed control
	// payloads.
	DisableSignatureVerification bool
}

func (c *Config) loadDefaults() {
	if c.HandlerTimeout == 0 {
		c.HandlerTimeout = DefaultHandlerTimeout
	}
}

var _ infra.Messenger = (*Messenger)(nil)

// Messenger exposes the API for sending and receiving CtrlPld messages.
type Messenger struct {
	config *Config
	// Networking layer for sending and receiving messages
	dispatcher *disp.Dispatcher

	cryptoLock sync.RWMutex
	// signer is used to sign selected outgoing messages
	signer ctrl.Signer
	// signMask specifies which messages are signed when sent out
	signMask map[infra.MessageType]struct{}
	// verifier is used to verify selected incoming messages
	verifier ctrl.SigVerifier

	// Source for crypto objects (certificates and TRCs)
	trustStore infra.TrustStore

	handlersLock sync.RWMutex
	// Handlers for received messages processing
	handlers map[infra.MessageType]infra.Handler

	closeLock sync.Mutex
	closeChan chan struct{}
	// Context passed to blocking receive. Canceled by Close to unblock listeners.
	ctx     context.Context
	cancelF context.CancelFunc

	ia  addr.IA
	log log.Logger
}

// New creates a new Messenger that uses dispatcher for sending and receiving
// messages, and trustStore as crypto information database.
func New(ia addr.IA, dispatcher *disp.Dispatcher, store infra.TrustStore, logger log.Logger,
	config *Config) *Messenger {

	if config == nil {
		config = &Config{}
	}
	config.loadDefaults()
	// XXX(scrye): A trustStore object is passed to the Messenger as it is required
	// to verify top-level signatures. This is never used right now since only
	// unsigned messages are supported. The content of received messages is
	// processed in the relevant handlers which have their own reference to the
	// trustStore.
	ctx, cancelF := context.WithCancel(context.Background())
	return &Messenger{
		ia:         ia,
		config:     config,
		dispatcher: dispatcher,
		signer:     ctrl.NullSigner,
		verifier:   ctrl.NullSigVerifier,
		trustStore: store,
		handlers:   make(map[infra.MessageType]infra.Handler),
		closeChan:  make(chan struct{}),
		ctx:        ctx,
		cancelF:    cancelF,
		log:        logger,
	}
}

// GetTRC sends a cert_mgmt.TRCReq request to address a, blocks until it receives a
// reply and returns the reply.
func (m *Messenger) GetTRC(ctx context.Context, msg *cert_mgmt.TRCReq,
	a net.Addr, id uint64) (*cert_mgmt.TRC, error) {

	debug_id := util.GetDebugID()
	logger := m.log.New("debug_id", debug_id)
	pld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return nil, err
	}
	logger.Debug("[Messenger] Sending request", "req_type", infra.TRCRequest,
		"msg_id", id, "request", msg, "peer", a)
	replyCtrlPld, _, err := m.getRequester(infra.TRCRequest, infra.TRC).Request(ctx, pld, a)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Request error", err, "debug_id", debug_id)
	}
	_, replyMsg, err := m.validate(replyCtrlPld)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Reply validation failed", err,
			"debug_id", debug_id)
	}
	reply, ok := replyMsg.(*cert_mgmt.TRC)
	if !ok {
		err := newTypeAssertErr("*cert_mgmt.TRC", replyMsg)
		return nil, common.NewBasicError("[Messenger] Type assertion failed", err,
			"debug_id", debug_id)
	}
	logger.Debug("[Messenger] Received reply", "reply", reply)
	return reply, nil
}

// SendTRC sends a reliable cert_mgmt.TRC to address a.
func (m *Messenger) SendTRC(ctx context.Context, msg *cert_mgmt.TRC, a net.Addr, id uint64) error {
	pld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return err
	}
	m.log.Debug("[Messenger] Sending Notify", "type", infra.TRC, "to", a, "id", id)
	return m.getRequester(infra.TRC, infra.None).Notify(ctx, pld, a)
}

// GetCertChain sends a cert_mgmt.ChainReq to address a, blocks until it
// receives a reply and returns the reply.
func (m *Messenger) GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq,
	a net.Addr, id uint64) (*cert_mgmt.Chain, error) {

	debug_id := util.GetDebugID()
	logger := m.log.New("debug_id", debug_id)
	pld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return nil, err
	}
	logger.Debug("[Messenger] Sending request", "req_type", infra.ChainRequest,
		"msg_id", id, "request", msg, "peer", a)
	replyCtrlPld, _, err := m.getRequester(infra.ChainRequest, infra.Chain).Request(ctx, pld, a)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Request error", err, "debug_id", debug_id)
	}
	_, replyMsg, err := m.validate(replyCtrlPld)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Reply validation failed", err,
			"debug_id", debug_id)
	}
	reply, ok := replyMsg.(*cert_mgmt.Chain)
	if !ok {
		err := newTypeAssertErr("*cert_mgmt.Chain", replyMsg)
		return nil, common.NewBasicError("[Messenger] Type assertion failed", err,
			"debug_id", debug_id)
	}
	logger.Debug("[Messenger] Received reply", "reply", reply)
	return reply, nil
}

// SendCertChain sends a reliable cert_mgmt.Chain to address a.
func (m *Messenger) SendCertChain(ctx context.Context, msg *cert_mgmt.Chain, a net.Addr,
	id uint64) error {

	pld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return err
	}
	m.log.Debug("[Messenger] Sending Notify", "type", infra.Chain, "to", a, "id", id)
	return m.getRequester(infra.Chain, infra.None).Notify(ctx, pld, a)
}

// GetSegs asks the server at the remote address for the path segments that
// satisfy msg, and returns a verified reply.
func (m *Messenger) GetSegs(ctx context.Context, msg *path_mgmt.SegReq,
	a net.Addr, id uint64) (*path_mgmt.SegReply, error) {

	debug_id := util.GetDebugID()
	logger := m.log.New("debug_id", debug_id)
	pld, err := ctrl.NewPathMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return nil, err
	}
	logger.Debug("[Messenger] Sending request", "req_type", infra.SegRequest,
		"msg_id", id, "request", msg, "peer", a)
	replyCtrlPld, _, err :=
		m.getRequester(infra.SegRequest, infra.SegReply).Request(ctx, pld, a)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Request error", err, "debug_id", debug_id)
	}
	_, replyMsg, err := m.validate(replyCtrlPld)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Reply validation failed", err,
			"debug_id", debug_id)
	}
	reply, ok := replyMsg.(*path_mgmt.SegReply)
	if !ok {
		err := newTypeAssertErr("*path_mgmt.SegReply", replyMsg)
		return nil, common.NewBasicError("[Messenger] Type assertion failed", err,
			"debug_id", debug_id)
	}
	if err := reply.ParseRaw(); err != nil {
		return nil, common.NewBasicError("[Messenger] Failed to parse reply", err,
			"debug_id", debug_id)
	}
	logger.Debug("[Messenger] Received reply")
	return reply, nil
}

// SendSegReply sends a reliable path_mgmt.SegReply to address a.
func (m *Messenger) SendSegReply(ctx context.Context,
	msg *path_mgmt.SegReply, a net.Addr, id uint64) error {

	pld, err := ctrl.NewPathMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return err
	}
	m.log.Debug("[Messenger] Sending Notify", "type", infra.SegReply, "to", a, "id", id)
	return m.getRequester(infra.SegReply, infra.None).Notify(ctx, pld, a)
}

// SendSegSync sends a reliable path_mgmt.SegSync to address a.
func (m *Messenger) SendSegSync(ctx context.Context,
	msg *path_mgmt.SegSync, a net.Addr, id uint64) error {

	pld, err := ctrl.NewPathMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return err
	}
	m.log.Debug("[Messenger] Sending Notify", "type", infra.SegSync, "to", a, "id", id)
	return m.getRequester(infra.SegSync, infra.None).Notify(ctx, pld, a)
}

func (m *Messenger) GetSegChangesIds(ctx context.Context, msg *path_mgmt.SegChangesIdReq,
	a net.Addr, id uint64) (*path_mgmt.SegChangesIdReply, error) {

	debug_id := util.GetDebugID()
	logger := m.log.New("debug_id", debug_id)
	pld, err := ctrl.NewPathMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return nil, err
	}
	logger.Debug("[Messenger] Sending request", "req_type", infra.SegChangesIdReq,
		"msg_id", id, "request", msg, "peer", a)
	replyCtrlPld, _, err := m.getRequester(infra.SegChangesIdReq,
		infra.SegChangesIdReply).Request(ctx, pld, a)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Request error", err, "debug_id", debug_id)
	}
	_, replyMsg, err := m.validate(replyCtrlPld)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Reply validation failed", err,
			"debug_id", debug_id)
	}
	reply, ok := replyMsg.(*path_mgmt.SegChangesIdReply)
	if !ok {
		err := newTypeAssertErr("*path_mgmt.SegChangesIdReply", replyMsg)
		return nil, common.NewBasicError("[Messenger] Type assertion failed", err,
			"debug_id", debug_id)
	}
	logger.Debug("[Messenger] Received reply")
	return reply, nil
}

func (m *Messenger) SendSegChangesIdReply(ctx context.Context,
	msg *path_mgmt.SegChangesIdReply, a net.Addr, id uint64) error {

	pld, err := ctrl.NewPathMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return err
	}
	m.log.Debug("[Messenger] Sending Notify",
		"type", infra.SegChangesIdReply, "to", a, "id", id)
	return m.getRequester(infra.SegChangesIdReply, infra.None).Notify(ctx, pld, a)
}

func (m *Messenger) GetSegChanges(ctx context.Context, msg *path_mgmt.SegChangesReq,
	a net.Addr, id uint64) (*path_mgmt.SegChangesReply, error) {

	debug_id := util.GetDebugID()
	logger := m.log.New("debug_id", debug_id)
	pld, err := ctrl.NewPathMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return nil, err
	}
	logger.Debug("[Messenger] Sending request", "req_type", infra.SegChangesReq,
		"msg_id", id, "request", msg, "peer", a)
	replyCtrlPld, _, err := m.getRequester(infra.SegChangesReq,
		infra.SegChangesIdReply).Request(ctx, pld, a)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Request error", err, "debug_id", debug_id)
	}
	_, replyMsg, err := m.validate(replyCtrlPld)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Reply validation failed", err,
			"debug_id", debug_id)
	}
	reply, ok := replyMsg.(*path_mgmt.SegChangesReply)
	if !ok {
		err := newTypeAssertErr("*path_mgmt.SegChangesReply", replyMsg)
		return nil, common.NewBasicError("[Messenger] Type assertion failed", err,
			"debug_id", debug_id)
	}
	if err := reply.ParseRaw(); err != nil {
		return nil, common.NewBasicError("[Messenger] Failed to parse reply", err,
			"debug_id", debug_id)
	}
	logger.Debug("[Messenger] Received reply")
	return reply, nil
}

func (m *Messenger) SendSegChangesReply(ctx context.Context,
	msg *path_mgmt.SegChangesReply, a net.Addr, id uint64) error {

	pld, err := ctrl.NewPathMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return err
	}
	m.log.Debug("[Messenger] Sending Notify",
		"type", infra.SegChangesReply, "to", a, "id", id)
	return m.getRequester(infra.SegChangesReply, infra.None).Notify(ctx, pld, a)
}

func (m *Messenger) RequestChainIssue(ctx context.Context, msg *cert_mgmt.ChainIssReq, a net.Addr,
	id uint64) (*cert_mgmt.ChainIssRep, error) {

	debug_id := util.GetDebugID()
	logger := m.log.New("debug_id", debug_id)
	pld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return nil, err
	}
	logger.Debug("[Messenger] Sending request", "req_type", infra.ChainIssueRequest,
		"msg_id", id, "request", msg, "peer", a)
	replyCtrlPld, _, err :=
		m.getRequester(infra.ChainIssueRequest, infra.ChainIssueReply).Request(ctx, pld, a)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Request error", err, "debug_id", debug_id)
	}
	_, replyMsg, err := m.validate(replyCtrlPld)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Reply validation failed", err,
			"debug_id", debug_id)
	}
	reply, ok := replyMsg.(*cert_mgmt.ChainIssRep)
	if !ok {
		err := newTypeAssertErr("*cert_mgmt.ChainIssRep", replyMsg)
		return nil, common.NewBasicError("[Messenger] Type assertion failed", err,
			"debug_id", debug_id)
	}
	logger.Debug("[Messenger] Received reply")
	return reply, nil
}

func (m *Messenger) SendChainIssueReply(ctx context.Context, msg *cert_mgmt.ChainIssRep,
	a net.Addr, id uint64) error {

	pld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return err
	}
	m.log.Debug("[Messenger] Sending Notify", "type", infra.ChainIssueReply, "to", a, "id", id)
	return m.getRequester(infra.ChainIssueReply, infra.None).Notify(ctx, pld, a)
}

// AddHandler registers a handler for msgType.
func (m *Messenger) AddHandler(msgType infra.MessageType, handler infra.Handler) {
	m.handlersLock.Lock()
	m.handlers[msgType] = handler
	m.handlersLock.Unlock()
}

// ListenAndServe starts listening and serving messages on srv's Messenger
// interface. The function runs in the current goroutine. Multiple
// ListenAndServe methods can run in parallel.
func (m *Messenger) ListenAndServe() {
	m.log.Info("Started listening")
	defer m.log.Info("Stopped listening")
	for {
		// Recv blocks until a new message is received. To close the server,
		// CloseServer() calls the context's cancel function, thus unblocking Recv. The
		// server's main loop then detects that closeChan has been closed, and shuts
		// down cleanly.
		genericMsg, address, err := m.dispatcher.RecvFrom(m.ctx)
		if err != nil {
			// Do not log errors caused after close signal sent
			select {
			case <-m.closeChan:
				// CloseServer was called
				return
			default:
				m.log.Error("Receive error", "err", err)
			}
			continue
		}
		logger := m.log.New("debug_id", util.GetDebugID())

		signedPld, ok := genericMsg.(*ctrl.SignedPld)
		if !ok {
			logger.Error("Type assertion failure", "from", address, "expected", "*ctrl.SignedPld",
				"actual", common.TypeOf(genericMsg))
			continue
		}

		serveCtx := infra.NewContextWithMessenger(m.ctx, m)
		serveCtx, serveCancelF := context.WithTimeout(serveCtx, m.config.HandlerTimeout)
		if !m.config.DisableSignatureVerification {
			// FIXME(scrye): Always use default signature verifier here, as some
			// functionality in the main ctrl libraries is still missing.
			err = m.verifySignedPld(serveCtx, signedPld, m.verifier, address.(*snet.Addr))
			if err != nil {
				logger.Error("Verification error", "from", address, "err", err)
				serveCancelF()
				continue
			}
		}

		pld, err := signedPld.Pld()
		if err != nil {
			logger.Error("Unable to extract Pld from CtrlPld", "from", address, "err", err)
			serveCancelF()
			continue
		}
		m.serve(serveCtx, serveCancelF, pld, signedPld, address, logger)
	}
}

func (m *Messenger) verifySignedPld(ctx context.Context, signedPld *ctrl.SignedPld,
	verifier ctrl.SigVerifier, addr *snet.Addr) error {

	if signedPld.Sign == nil || signedPld.Sign.Type == proto.SignType_none {
		return nil
	}
	src, err := ctrl.NewSignSrcDefFromRaw(signedPld.Sign.Src)
	if err != nil {
		return err
	}
	if err := ctrl.VerifySig(ctx, signedPld, verifier); err != nil {
		return common.NewBasicError("Unable to verify signature", err)
	}
	if !addr.IA.Eq(src.IA) {
		return common.NewBasicError("Sender IA does not match signed src IA", nil,
			"expected", src.IA, "actual", addr.IA)
	}
	return nil
}

func (m *Messenger) serve(ctx context.Context, cancelF context.CancelFunc, pld *ctrl.Pld,
	signedPld *ctrl.SignedPld, address net.Addr, logger log.Logger) {

	// Validate that the message is of acceptable type, and that its top-level
	// signature is correct.
	msgType, msg, err := m.validate(pld)
	if err != nil {
		logger.Error("Received message, but unable to validate message",
			"from", address, "err", err)
		return
	}
	logger.Debug("[Messenger] Received message", "type", msgType, "from", address, "id", pld.ReqId)

	m.handlersLock.RLock()
	handler := m.handlers[msgType]
	m.handlersLock.RUnlock()
	if handler == nil {
		logger.Error("Received message, but handler not found", "from", address,
			"msgType", msgType)
		return
	}
	go func() {
		defer cancelF()
		defer log.LogPanicAndExit()
		handler.Handle(infra.NewRequest(ctx, msg, signedPld, address, pld.ReqId, logger))
	}()
}

// validate checks that msg is one of the acceptable message types for SCION
// infra communication (listed in package level documentation), and returns the
// message type, the message (the inner proto.Cerealizable object), and an
// error (if one occurred).
func (m *Messenger) validate(pld *ctrl.Pld) (infra.MessageType, proto.Cerealizable, error) {
	// XXX(scrye): For now, only the messages in the top comment of this
	// package are supported.
	switch pld.Which {
	case proto.CtrlPld_Which_certMgmt:
		switch pld.CertMgmt.Which {
		case proto.CertMgmt_Which_certChainReq:
			return infra.ChainRequest, pld.CertMgmt.ChainReq, nil
		case proto.CertMgmt_Which_certChain:
			return infra.Chain, pld.CertMgmt.ChainRep, nil
		case proto.CertMgmt_Which_trcReq:
			return infra.TRCRequest, pld.CertMgmt.TRCReq, nil
		case proto.CertMgmt_Which_trc:
			return infra.TRC, pld.CertMgmt.TRCRep, nil
		case proto.CertMgmt_Which_certChainIssReq:
			return infra.ChainIssueRequest, pld.CertMgmt.ChainIssReq, nil
		case proto.CertMgmt_Which_certChainIssRep:
			return infra.ChainIssueReply, pld.CertMgmt.ChainIssRep, nil
		default:
			return infra.None, nil,
				common.NewBasicError("Unsupported SignedPld.CtrlPld.CertMgmt.Xxx message type",
					nil, "capnp_which", pld.CertMgmt.Which)
		}
	case proto.CtrlPld_Which_pathMgmt:
		switch pld.PathMgmt.Which {
		case proto.PathMgmt_Which_segReq:
			return infra.SegRequest, pld.PathMgmt.SegReq, nil
		case proto.PathMgmt_Which_segReply:
			return infra.SegReply, pld.PathMgmt.SegReply, nil
		case proto.PathMgmt_Which_segReg:
			return infra.SegReg, pld.PathMgmt.SegReg, nil
		case proto.PathMgmt_Which_segSync:
			return infra.SegSync, pld.PathMgmt.SegSync, nil
		case proto.PathMgmt_Which_sRevInfo:
			return infra.SegRev, pld.PathMgmt.SRevInfo, nil
		case proto.PathMgmt_Which_ifStateInfos:
			return infra.IfStateInfos, pld.PathMgmt.IFStateInfos, nil
		case proto.PathMgmt_Which_segChangesIdReq:
			return infra.SegChangesIdReq, pld.PathMgmt.SegChangesIdReq, nil
		case proto.PathMgmt_Which_segChangesIdReply:
			return infra.SegChangesIdReply, pld.PathMgmt.SegChangesIdReply, nil
		case proto.PathMgmt_Which_segChangesReq:
			return infra.SegChangesReq, pld.PathMgmt.SegChangesReq, nil
		case proto.PathMgmt_Which_segChangesReply:
			return infra.SegChangesReply, pld.PathMgmt.SegChangesReply, nil
		default:
			return infra.None, nil,
				common.NewBasicError("Unsupported SignedPld.CtrlPld.PathMgmt.Xxx message type",
					nil, "capnp_which", pld.PathMgmt.Which)
		}
	default:
		return infra.None, nil, common.NewBasicError("Unsupported SignedPld.Pld.Xxx message type",
			nil, "capnp_which", pld.Which)
	}
}

// CloseServer stops any running ListenAndServe functions, and cancels all running
// handlers. The server's Messenger layer is not closed.
func (m *Messenger) CloseServer() error {
	// Protect against concurrent Close calls
	m.closeLock.Lock()
	defer m.closeLock.Unlock()
	select {
	case <-m.closeChan:
		// Already closed, so do nothing
	default:
		close(m.closeChan)
		m.cancelF()
	}
	return nil
}

// UpdateSigner enables signing of messages with signer. Only the messages in
// types are signed, the rest are left with a null signature. If types is nil,
// only the signer is updated and the existing internal list of types is
// unchanged. An empty slice of types disables signing for all messages.
func (m *Messenger) UpdateSigner(signer ctrl.Signer, types []infra.MessageType) {
	m.cryptoLock.Lock()
	defer m.cryptoLock.Unlock()
	if types != nil {
		m.signMask = make(map[infra.MessageType]struct{})
		for _, t := range types {
			m.signMask[t] = struct{}{}
		}
	}
	m.signer = signer
}

// UpdateVerifier enables verifying of messages with verifier.
//
// FIXME(scrye): Verifiers are usually bound to a trust store to which the
// messenger already holds a reference. We should decouple the trust store from
// either one or the other.
func (m *Messenger) UpdateVerifier(verifier ctrl.SigVerifier) {
	m.cryptoLock.Lock()
	defer m.cryptoLock.Unlock()
	m.verifier = verifier
}

// getRequester returns a requester object with customized crypto keys.
//
// If message type reqT is to be signed, the key is initialized from m.signer.
// Otherwise it is set to a null signer.
//
// If message type respT is to be verified, the key is initialized from
// m.verifier. Otherwise, it is set to a null verifier.
func (m *Messenger) getRequester(reqT, respT infra.MessageType) *pathingRequester {
	m.cryptoLock.RLock()
	defer m.cryptoLock.RUnlock()
	signer := ctrl.NullSigner
	if _, ok := m.signMask[reqT]; ok {
		signer = m.signer
	}
	return NewPathingRequester(signer, m.verifier, m.dispatcher, m.ia)
}

func newTypeAssertErr(typeStr string, msg interface{}) error {
	errStr := fmt.Sprintf("Unable to type assert disp.Message to %s", typeStr)
	return common.NewBasicError(errStr, nil, "msg", msg)
}

// pathingRequester is a requester with an attached local IA. It resolves the
// SCION path to construct complete snet addresses that rarely block on writes.
//
// FIXME(scrye): This is just a hack to improve performance in the default
// topology, by allowing each goroutine to issue a request to SCIOND in
// parallel (as opposed of one goroutine waiting for another if the Path
// Resolver were to be used). This logic should be moved to snet internals
// once the path resolver has support for concurrent queries and context
// awareness.
type pathingRequester struct {
	requester *ctrl_msg.Requester
	local     addr.IA
}

func NewPathingRequester(signer ctrl.Signer, sigv ctrl.SigVerifier, d *disp.Dispatcher,
	local addr.IA) *pathingRequester {

	return &pathingRequester{
		requester: ctrl_msg.NewRequester(signer, sigv, d),
		local:     local,
	}
}

func (pr *pathingRequester) Request(ctx context.Context, pld *ctrl.Pld,
	a net.Addr) (*ctrl.Pld, *proto.SignS, error) {

	newAddr, err := pr.getBlockingPath(a)
	if err != nil {
		return nil, nil, err
	}
	return pr.requester.Request(ctx, pld, newAddr)
}

func (pr *pathingRequester) Notify(ctx context.Context, pld *ctrl.Pld, a net.Addr) error {
	newAddr, err := pr.getBlockingPath(a)
	if err != nil {
		return err
	}
	return pr.requester.Notify(ctx, pld, newAddr)
}

func (pr *pathingRequester) NotifyUnreliable(ctx context.Context, pld *ctrl.Pld, a net.Addr) error {
	newAddr, err := pr.getBlockingPath(a)
	if err != nil {
		return err
	}
	return pr.requester.NotifyUnreliable(ctx, pld, newAddr)
}

func (pr *pathingRequester) getBlockingPath(a net.Addr) (net.Addr, error) {
	// for SCIOND-less operation do not try to resolve paths
	if snet.DefNetwork == nil || snet.DefNetwork.PathResolver() == nil {
		return a, nil
	}
	snetAddress := a.(*snet.Addr).Copy()
	if snetAddress.IA == pr.local {
		return snetAddress, nil
	}
	sdService := snet.DefNetwork.PathResolver().Sciond()
	conn, err := sdService.Connect()
	if err != nil {
		return nil, err
	}
	paths, err := conn.Paths(snetAddress.IA, pr.local, 5, sciond.PathReqFlags{})
	if err != nil {
		return nil, err
	}
	if len(paths.Entries) == 0 {
		return nil, common.NewBasicError("unable to find path", nil)
	}
	snetAddress.Path = spath.New(paths.Entries[0].Path.FwdPath)
	snetAddress.NextHop, err = paths.Entries[0].HostInfo.Overlay()
	if err != nil {
		return nil, common.NewBasicError("unable to build next hop", err)
	}
	return snetAddress, nil
}
