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
// The following message types are valid messages. At the moment, no signature
// verification is performed on the SignedPld.
//  ChainRequest -> ctrl.SignedPld/ctrl.Pld/cert_mgmt.ChainReq
//  Chain        -> ctrl.SignedPld/ctrl.Pld/cert_mgmt.Chain
//  TRCRequest   -> ctrl.SignedPld/ctrl.Pld/cert_mgmt.TRCReq
//  TRC          -> ctrl.SignedPld/ctrl.Pld/cert_mgmt.TRC
//  PathRequest  -> ctrl.SignedPld/ctrl.Pld/path_mgmt.SegReq
//
// The word "reliable" in method descriptions means a reliable protocol is used
// to deliver that message.
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
//   msger.AddHandler(ChainRequest, MyCustomHandler)
//   msger.AddHandler(TRCRequest, MyOtherCustomHandler)
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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/ctrl_msg"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

const (
	ChainRequest       = "ChainRequest"
	Chain              = "Chain"
	TRCRequest         = "TRCRequest"
	TRC                = "TRC"
	PathSegmentRequest = "PathSegmentRequest"
	PathSegmentReply   = "PathSegmentReply"
	ChainIssueRequest  = "ChainIssueRequest"
	ChainIssueReply    = "ChainIssueReply"
)

var _ infra.Messenger = (*Messenger)(nil)

// Messenger exposes the API for sending and receiving CtrlPld messages.
type Messenger struct {
	// Networking layer for sending and receiving messages
	dispatcher *disp.Dispatcher

	cryptoLock sync.RWMutex
	// signer is used to sign selected outgoing messages
	signer ctrl.Signer
	// signMask specifies which messages are signed when sent out
	signMask map[string]struct{}
	// verifier is used to verify selected incoming messages
	verifier ctrl.SigVerifier

	// Source for crypto objects (certificates and TRCs)
	trustStore infra.TrustStore

	handlersLock sync.RWMutex
	// Handlers for received messages processing
	handlers map[string]infra.Handler

	closeLock sync.Mutex
	closeChan chan struct{}
	// Context passed to blocking receive. Canceled by Close to unblock listeners.
	ctx     context.Context
	cancelF context.CancelFunc

	log log.Logger
}

// New creates a new Messenger that uses dispatcher for sending and receiving
// messages, and trustStore as crypto information database.
func New(dispatcher *disp.Dispatcher, store infra.TrustStore, logger log.Logger) *Messenger {
	// XXX(scrye): A trustStore object is passed to the Messenger as it is required
	// to verify top-level signatures. This is never used right now since only
	// unsigned messages are supported. The content of received messages is
	// processed in the relevant handlers which have their own reference to the
	// trustStore.
	ctx, cancelF := context.WithCancel(context.Background())
	return &Messenger{
		dispatcher: dispatcher,
		signer:     ctrl.NullSigner,
		verifier:   ctrl.NullSigVerifier,
		trustStore: store,
		handlers:   make(map[string]infra.Handler),
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

	pld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return nil, err
	}
	m.log.Debug("[Messenger] Sending Request", "type", TRCRequest, "to", a, "id", id)
	replyCtrlPld, _, err := m.getRequester(TRCRequest, TRC).Request(ctx, pld, a)
	if err != nil {
		return nil, err
	}
	_, replyMsg, err := m.validate(replyCtrlPld)
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
func (m *Messenger) SendTRC(ctx context.Context, msg *cert_mgmt.TRC, a net.Addr, id uint64) error {
	pld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return err
	}
	m.log.Debug("[Messenger] Sending Notify", "type", TRC, "to", a, "id", id)
	return m.getRequester(TRC, "").Notify(ctx, pld, a)
}

// GetCertChain sends a cert_mgmt.ChainReq to address a, blocks until it
// receives a reply and returns the reply.
func (m *Messenger) GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq,
	a net.Addr, id uint64) (*cert_mgmt.Chain, error) {

	pld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return nil, err
	}
	m.log.Debug("[Messenger] Sending Request", "type", ChainRequest, "to", a, "id", id)
	replyCtrlPld, _, err := m.getRequester(ChainRequest, Chain).Request(ctx, pld, a)
	if err != nil {
		return nil, err
	}
	_, replyMsg, err := m.validate(replyCtrlPld)
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
func (m *Messenger) SendCertChain(ctx context.Context, msg *cert_mgmt.Chain, a net.Addr,
	id uint64) error {

	pld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return err
	}
	m.log.Debug("[Messenger] Sending Notify", "type", Chain, "to", a, "id", id)
	return m.getRequester(Chain, "").Notify(ctx, pld, a)
}

// GetPathSegs asks the server at the remote address for the path segments that
// satisfy msg, and returns a verified reply.
func (m *Messenger) GetPathSegs(ctx context.Context, msg *path_mgmt.SegReq,
	a net.Addr, id uint64) (*path_mgmt.SegReply, error) {

	pld, err := ctrl.NewPathMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return nil, err
	}
	m.log.Debug("[Messenger] Sending Request", "type", PathSegmentRequest, "to", a, "id", id)
	replyCtrlPld, _, err := m.getRequester(PathSegmentRequest, PathSegmentReply).Request(ctx, pld, a)
	if err != nil {
		return nil, err
	}
	_, replyMsg, err := m.validate(replyCtrlPld)
	if err != nil {
		return nil, err
	}
	reply, ok := replyMsg.(*path_mgmt.SegReply)
	if !ok {
		return nil, newTypeAssertErr("*path_mgmt.SegReply", replyMsg)
	}
	if err := reply.ParseRaw(); err != nil {
		return nil, err
	}
	return reply, nil
}

func (m *Messenger) RequestChainIssue(ctx context.Context, msg *cert_mgmt.ChainIssReq, a net.Addr,
	id uint64) (*cert_mgmt.ChainIssRep, error) {

	pld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return nil, err
	}
	m.log.Debug("[Messenger] Sending Request", "type", ChainIssueRequest, "to", a, "id", id)
	replyCtrlPld, _, err := m.getRequester(ChainIssueRequest, ChainIssueReply).Request(ctx, pld, a)
	if err != nil {
		return nil, err
	}
	_, replyMsg, err := m.validate(replyCtrlPld)
	if err != nil {
		return nil, err
	}
	reply, ok := replyMsg.(*cert_mgmt.ChainIssRep)
	if !ok {
		return nil, newTypeAssertErr("*cert_mgmt.ChainIssReply", replyMsg)
	}
	return reply, nil
}

func (m *Messenger) SendChainIssueReply(ctx context.Context, msg *cert_mgmt.ChainIssRep, a net.Addr, id uint64) error {

	pld, err := ctrl.NewCertMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return err
	}
	m.log.Debug("[Messenger] Sending Notify", "type", ChainIssueReply, "to", a, "id", id)
	return m.getRequester(ChainIssueReply, "").Notify(ctx, pld, a)
}

// AddHandler registers a handler for msgType.
func (m *Messenger) AddHandler(msgType string, handler infra.Handler) {
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

		signedPld, ok := genericMsg.(*ctrl.SignedPld)
		if !ok {
			m.log.Error("Type assertion failure", "from", address, "expected", "*ctrl.SignedPld",
				"actual", common.TypeOf(genericMsg))
			continue
		}

		// Skip top-level signature verification if running on top of non-snet
		// transports because we cannot detect the signer's identity.
		if a, ok := address.(*snet.Addr); ok {
			// FIXME(scrye): Always use default signature verifier here, as some
			// functionality in the main ctrl libraries is still missing.
			err = m.verifySignedPld(signedPld, m.verifier, a)
			if err != nil {
				m.log.Error("Verification error", "from", address, "err", err)
				continue
			}
		}

		pld, err := signedPld.Pld()
		if err != nil {
			m.log.Error("Unable to extract Pld from CtrlPld", "from", address, "err", err)
			continue
		}
		m.serve(pld, signedPld, address)
	}
}

func (m *Messenger) verifySignedPld(signedPld *ctrl.SignedPld, verifier ctrl.SigVerifier,
	addr *snet.Addr) error {

	if signedPld.Sign == nil {
		return nil
	}
	if err := ctrl.VerifySig(signedPld, verifier); err != nil {
		return common.NewBasicError("Unable to verify signature", err)
	}
	if signedPld.Sign.Type == proto.SignType_none {
		return nil
	}
	src, err := ctrl.NewSignSrcDefFromRaw(signedPld.Sign.Src)
	if err != nil {
		return err
	}
	if !addr.IA.Eq(src.IA) {
		return common.NewBasicError("Sender IA does not match signed src IA", nil,
			"expected", src.IA, "actual", addr.IA)
	}
	return nil
}

func (m *Messenger) serve(pld *ctrl.Pld, signedPld *ctrl.SignedPld, address net.Addr) {
	// Validate that the message is of acceptable type, and that its top-level
	// signature is correct.
	msgType, msg, err := m.validate(pld)
	if err != nil {
		m.log.Error("Received message, but unable to validate message", "from", address, "err", err)
		return
	}
	m.log.Debug("[Messenger] Received Message", "type", msgType, "from", address, "id", pld.ReqId)

	m.handlersLock.RLock()
	handler := m.handlers[msgType]
	m.handlersLock.RUnlock()
	if handler == nil {
		m.log.Error("Received message, but handler not found", "from", address,
			"msgType", msgType)
		return
	}
	serveCtx := infra.NewContextWithMessenger(m.ctx, m)
	go handler.Handle(infra.NewRequest(serveCtx, msg, signedPld, address, pld.ReqId))
}

// validate checks that msg is one of the acceptable message types for SCION
// infra communication (listed in package level documentation), and returns the
// message type ID string, the message (the inner proto.Cerealizable object),
// and an error (if one occurred).
func (m *Messenger) validate(pld *ctrl.Pld) (string, proto.Cerealizable, error) {
	// XXX(scrye): For now, only the messages in the top comment of this
	// package are supported.
	switch pld.Which {
	case proto.CtrlPld_Which_certMgmt:
		switch pld.CertMgmt.Which {
		case proto.CertMgmt_Which_certChainReq:
			return ChainRequest, pld.CertMgmt.ChainReq, nil
		case proto.CertMgmt_Which_certChain:
			return Chain, pld.CertMgmt.ChainRep, nil
		case proto.CertMgmt_Which_trcReq:
			return TRCRequest, pld.CertMgmt.TRCReq, nil
		case proto.CertMgmt_Which_trc:
			return TRC, pld.CertMgmt.TRCRep, nil
		case proto.CertMgmt_Which_certChainIssReq:
			return ChainIssueRequest, pld.CertMgmt.ChainIssReq, nil
		case proto.CertMgmt_Which_certChainIssRep:
			return ChainIssueReply, pld.CertMgmt.ChainIssRep, nil
		default:
			return "", nil,
				common.NewBasicError("Unsupported SignedPld.CtrlPld.CertMgmt.Xxx message type",
					nil, "capnp_which", pld.CertMgmt.Which)
		}
	case proto.CtrlPld_Which_pathMgmt:
		switch pld.PathMgmt.Which {
		case proto.PathMgmt_Which_segReq:
			return PathSegmentRequest, pld.PathMgmt.SegReq, nil
		case proto.PathMgmt_Which_segReply:
			return PathSegmentReply, pld.PathMgmt.SegReply, nil
		default:
			return "", nil,
				common.NewBasicError("Unsupported SignedPld.CtrlPld.PathMgmt.Xxx message type",
					nil, "capnp_which", pld.PathMgmt.Which)
		}
	default:
		return "", nil, common.NewBasicError("Unsupported SignedPld.Pld.Xxx message type",
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
// types are signed, the rest are left with a null signature.
func (m *Messenger) UpdateSigner(signer ctrl.Signer, types []string) {
	m.cryptoLock.Lock()
	defer m.cryptoLock.Unlock()
	m.signMask = make(map[string]struct{})
	for _, t := range types {
		m.signMask[t] = struct{}{}
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
func (m *Messenger) getRequester(reqT, respT string) *ctrl_msg.Requester {
	m.cryptoLock.RLock()
	defer m.cryptoLock.RUnlock()
	signer := ctrl.NullSigner
	if _, ok := m.signMask[reqT]; ok {
		signer = m.signer
	}
	return ctrl_msg.NewRequester(signer, m.verifier, m.dispatcher)
}

func newTypeAssertErr(typeStr string, msg interface{}) error {
	errStr := fmt.Sprintf("Unable to type assert disp.Message to %s", typeStr)
	return common.NewBasicError(errStr, nil, "msg", msg)
}
