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
//  infra.IfId                -> ctrl.SignedPld/ctrl.Pld/ifid.IFID
//  infra.HPSegReg            -> ctrl.SignedPld/ctrl.Pld/path_mgmt.HPSegReg
//  infra.HPSegRequest        -> ctrl.SignedPld/ctrl.Pld/path_mgmt.HPSegReq
//  infra.HPSegReply          -> ctrl.SignedPld/ctrl.Pld/path_mgmt.HPSegReply
//  infra.HPCfgRequest        -> ctrl.SignedPld/ctrl.Pld/path_mgmt.HPCfgReq
//  infra.HPCfgReply          -> ctrl.SignedPld/ctrl.Pld/path_mgmt.HPCfgReply
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
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	opentracingext "github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/ctrl_msg"
	"github.com/scionproto/scion/go/lib/ctrl/ifid"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger/internal/metrics"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/proto"
)

const (
	DefaultHandlerTimeout = 10 * time.Second
)

// Config can be used to customize the behavior of the Messenger.
type Config struct {
	// IA is the local ISD-AS number.
	IA addr.IA
	// Dispatcher to use for associating requests with replies.
	Dispatcher *disp.Dispatcher
	// AddressRewriter is used to compute paths and replace SVC destinations with
	// unicast addresses.
	AddressRewriter *AddressRewriter
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

func (c *Config) InitDefaults() {
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

	// addressRewriter is used to compute full remote addresses (path + server)
	addressRewriter *AddressRewriter

	handlersLock sync.RWMutex
	// Handlers for received messages processing
	handlers map[infra.MessageType]infra.Handler

	closeLock sync.Mutex
	closeChan chan struct{}
	// Context passed to blocking receive. Canceled by Close to unblock listeners.
	ctx     context.Context
	cancelF context.CancelFunc

	ia addr.IA
}

// New creates a new Messenger based on config.
func New(config *Config) *Messenger {
	if config == nil {
		config = &Config{}
	}
	config.InitDefaults()

	// Parent context for all handlers
	ctx, cancelF := context.WithCancel(context.Background())

	// XXX(scrye): A trustStore object is passed to the Messenger as it is required
	// to verify top-level signatures. This is never used right now since only
	// unsigned messages are supported. The content of received messages is
	// processed in the relevant handlers which have their own reference to the
	// trustStore.
	return &Messenger{
		ia:              config.IA,
		config:          config,
		dispatcher:      config.Dispatcher,
		addressRewriter: config.AddressRewriter,
		handlers:        make(map[infra.MessageType]infra.Handler),
		closeChan:       make(chan struct{}),
		ctx:             ctx,
		cancelF:         cancelF,
	}
}

func (m *Messenger) SendAck(ctx context.Context, msg *ack.Ack, a net.Addr, id uint64) error {
	pld, err := ctrl.NewPld(msg, &ctrl.Data{ReqId: id})
	if err != nil {
		return err
	}
	logger := log.FromCtx(ctx)
	logger.Debug("[Messenger] Sending Ack", "to", a, "id", id)
	return m.getFallbackRequester(infra.Ack).Notify(ctx, pld, a)
}

func (m *Messenger) SendIfId(ctx context.Context, msg *ifid.IFID, a net.Addr, id uint64) error {
	return m.sendMessage(ctx, msg, a, id, infra.IfId)
}

func (m *Messenger) SendHPSegReg(ctx context.Context, msg *path_mgmt.HPSegReg, a net.Addr,
	id uint64) error {

	pld, err := path_mgmt.NewPld(msg, nil)
	if err != nil {
		return err
	}
	return m.sendMessage(ctx, pld, a, id, infra.HPSegReg)
}

func (m *Messenger) GetHPSegs(ctx context.Context, msg *path_mgmt.HPSegReq, a net.Addr,
	id uint64) (*path_mgmt.HPSegReply, error) {

	logger := log.FromCtx(ctx)
	data := &ctrl.Data{ReqId: id, TraceId: tracing.IDFromCtx(ctx)}
	pld, err := ctrl.NewPathMgmtPld(msg, nil, data)
	if err != nil {
		return nil, err
	}
	logger.Debug("[Messenger] Sending request", "req_type", infra.HPSegRequest,
		"msg_id", id, "request", msg, "peer", a)
	replyCtrlPld, err := m.getFallbackRequester(infra.HPSegRequest).Request(ctx, pld, a, false)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Request error", err,
			"req_type", infra.HPSegRequest)
	}
	_, replyMsg, err := Validate(replyCtrlPld)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Reply validation failed", err)
	}
	switch reply := replyMsg.(type) {
	case *path_mgmt.HPSegReply:
		if err := reply.ParseRaw(); err != nil {
			return nil, common.NewBasicError("[Messenger] Failed to parse reply", err)
		}
		logger.Debug("[Messenger] Received reply", "req_id", id)
		return reply, nil
	case *ack.Ack:
		return nil, &infra.Error{Message: reply}
	default:
		err := newTypeAssertErr("*path_mgmt.HPSegReply", replyMsg)
		return nil, common.NewBasicError("[Messenger] Type assertion failed", err)
	}
}

func (m *Messenger) SendHPSegReply(ctx context.Context, msg *path_mgmt.HPSegReply, a net.Addr,
	id uint64) error {

	pld, err := ctrl.NewPathMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return err
	}
	logger := log.FromCtx(ctx)
	logger.Debug("[Messenger] Sending Notify", "type", infra.HPSegReply, "to", a, "id", id)
	return m.getFallbackRequester(infra.HPSegReply).Notify(ctx, pld, a)
}

func (m *Messenger) GetHPCfgs(ctx context.Context, msg *path_mgmt.HPCfgReq, a net.Addr,
	id uint64) (*path_mgmt.HPCfgReply, error) {

	logger := log.FromCtx(ctx)
	data := &ctrl.Data{ReqId: id, TraceId: tracing.IDFromCtx(ctx)}
	pld, err := ctrl.NewPathMgmtPld(msg, nil, data)
	if err != nil {
		return nil, err
	}
	logger.Debug("[Messenger] Sending request", "req_type", infra.HPCfgRequest,
		"msg_id", id, "request", msg, "peer", a)
	replyCtrlPld, err := m.getFallbackRequester(infra.HPCfgRequest).Request(ctx, pld, a, false)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Request error", err,
			"req_type", infra.HPCfgRequest)
	}
	_, replyMsg, err := Validate(replyCtrlPld)
	if err != nil {
		return nil, common.NewBasicError("[Messenger] Reply validation failed", err)
	}
	switch reply := replyMsg.(type) {
	case *path_mgmt.HPCfgReply:
		logger.Debug("[Messenger] Received reply", "req_id", id)
		return reply, nil
	case *ack.Ack:
		return nil, &infra.Error{Message: reply}
	default:
		err := newTypeAssertErr("*path_mgmt.HPCfgReply", replyMsg)
		return nil, common.NewBasicError("[Messenger] Type assertion failed", err)
	}
}

func (m *Messenger) SendHPCfgReply(ctx context.Context, msg *path_mgmt.HPCfgReply, a net.Addr,
	id uint64) error {

	pld, err := ctrl.NewPathMgmtPld(msg, nil, &ctrl.Data{ReqId: id})
	if err != nil {
		return err
	}
	logger := log.FromCtx(ctx)
	logger.Debug("[Messenger] Sending Notify", "type", infra.HPCfgReply, "to", a, "id", id)
	return m.getFallbackRequester(infra.HPCfgReply).Notify(ctx, pld, a)
}

// sendMessage sends payload msg of type expectedType to address a, using id.
// If waiting for Acks is disabled, sendMessage returns immediately after
// sending the message on the network. If waiting for Acks is enabled,
// sendMessage blocks until an Ack is received from the peer. If the Ack
// contains an error, the returned error is non-nil. If the received message
// is not an Ack, an error is returned.
func (m *Messenger) sendMessage(ctx context.Context, msg proto.Cerealizable, a net.Addr,
	id uint64, msgType infra.MessageType) error {

	pld, err := ctrl.NewPld(msg, &ctrl.Data{ReqId: id, TraceId: tracing.IDFromCtx(ctx)})
	if err != nil {
		return err
	}
	logger := log.FromCtx(ctx)
	logger.Debug("[Messenger] Sending Notify", "type", msgType, "to", a, "id", id)
	_, err = m.getFallbackRequester(msgType).Request(ctx, pld, a, true)
	return err
}

// AddHandler registers a handler for msgType.
func (m *Messenger) AddHandler(msgType infra.MessageType, handler infra.Handler) {
	m.handlersLock.Lock()
	defer m.handlersLock.Unlock()
	m.handlers[msgType] = handler
}

// ListenAndServe starts listening and serving messages on srv's Messenger
// interface. The function runs in the current goroutine. Multiple
// ListenAndServe methods can run in parallel.
func (m *Messenger) ListenAndServe() {
	m.listenAndServeUDP()
}

func (m *Messenger) listenAndServeUDP() {
	log.Info("Started listening UDP")
	defer log.Info("Stopped listening UDP")
	for {
		// Recv blocks until a new message is received. To close the server,
		// CloseServer() calls the context's cancel function, thus unblocking Recv. The
		// server's main loop then detects that closeChan has been closed, and shuts
		// down cleanly.
		genericMsg, size, address, err := m.dispatcher.RecvFrom(m.ctx)
		if err != nil {
			// Do not log errors caused after close signal sent
			select {
			case <-m.closeChan:
				// CloseServer was called
				return
			default:
				metrics.Dispatcher.Reads(metrics.ResultLabels{Result: metrics.ErrRead}).Inc()
				log.Error("Receive error", "err", err)
			}
			continue
		}
		signedPld, ok := genericMsg.(*ctrl.SignedPld)
		if !ok {
			metrics.Dispatcher.Reads(metrics.ResultLabels{Result: metrics.ErrInvalidReq}).Inc()
			log.Error("Type assertion failure", "from", address, "expected", "*ctrl.SignedPld",
				"actual", common.TypeOf(genericMsg))
			continue
		}

		serveCtx, serveCancelF := context.WithTimeout(m.ctx, m.config.HandlerTimeout)
		var pld *ctrl.Pld
		if !m.config.DisableSignatureVerification {
			// FIXME(scrye): Always use default signature verifier here, as some
			// functionality in the main ctrl libraries is still missing.
			switch address.(type) {
			case *snet.UDPAddr:
			default:
				metrics.Dispatcher.Reads(metrics.ResultLabels{Result: metrics.ErrInvalidReq}).Inc()
				log.Error("Type assertion failure", "from", address, "expected", "*snet.{,UDP}Addr",
					"actual", common.TypeOf(address))
				serveCancelF()
				continue
			}

			if pld, err = signedPld.GetVerifiedPld(serveCtx, infra.NullSigVerifier); err != nil {
				metrics.Dispatcher.Reads(metrics.ResultLabels{Result: metrics.ErrVerify}).Inc()
				log.Error("Verification error", "from", address, "err", err)
				serveCancelF()
				continue
			}
		} else {
			if pld, err = signedPld.UnsafePld(); err != nil {
				metrics.Dispatcher.Reads(metrics.ResultLabels{Result: metrics.ErrParse}).Inc()
				log.Error("Unable to extract Pld from CtrlPld", "from", address, "err", err)
				serveCancelF()
				continue
			}
		}
		m.serve(serveCtx, serveCancelF, pld, signedPld, size, address)
	}
}

func (m *Messenger) serve(parentCtx context.Context, cancelF context.CancelFunc, pld *ctrl.Pld,
	signedPld *ctrl.SignedPld, size int, address net.Addr) {

	// Validate that the message is of acceptable type, and that its top-level
	// signature is correct.
	msgType, msg, err := Validate(pld)
	if err != nil {
		metrics.Dispatcher.Reads(metrics.ResultLabels{Result: metrics.ErrValidate}).Inc()
		log.Error("Received message, but unable to validate message",
			"from", address, "err", err)
		return
	}

	rwCtx := infra.NewContextWithResponseWriter(parentCtx,
		&UDPResponseWriter{
			Messenger: m,
			Remote:    address,
			ID:        pld.ReqId,
		},
	)

	// Tracing
	var spanCtx opentracing.SpanContext
	if len(pld.Data.TraceId) > 0 {
		var err error
		spanCtx, err = opentracing.GlobalTracer().Extract(opentracing.Binary,
			bytes.NewReader(pld.Data.TraceId))
		if err != nil {
			log.Info("Failed to extract span", "err", err)
		}
	}

	span, ctx := tracing.CtxWith(rwCtx, fmt.Sprintf("%s-handler-udp", msgType),
		opentracingext.RPCServerOption(spanCtx))
	ia, peer := extractPeer(address)
	span.SetTag("peer.isd_as", ia)
	span.SetTag("peer.address", peer)
	logger := log.FromCtx(ctx)

	logger.Debug("[Messenger] Received message", "type", msgType, "from", address, "id", pld.ReqId)

	m.handlersLock.RLock()
	handler := m.handlers[msgType]
	m.handlersLock.RUnlock()
	if handler == nil {
		metrics.Dispatcher.Reads(metrics.ResultLabels{Result: metrics.ErrInvalidReq}).Inc()
		// TODO(lukedirtwalker): Remove once we expect Acks everywhere.
		// Until then silently drop Acks so that we don't fill the logs.
		if msgType == infra.Ack {
			return
		}
		logger.Error("Received message, but handler not found", "from", address,
			"msgType", msgType, "id", pld.ReqId)
		return
	}
	metrics.Dispatcher.Reads(metrics.ResultLabels{Result: metrics.OkSuccess}).Inc()
	metrics.Dispatcher.ReadSizes().Observe(float64(size))

	go func() {
		defer log.HandlePanic()
		defer cancelF()
		defer span.Finish()
		handler.Handle(infra.NewRequest(ctx, msg, signedPld, address, pld.ReqId))
	}()
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

// getFallbackRequester returns a requester object with customized crypto keys.
// If QUIC is enabled, it first tries to do the Request over QUIC; if QUIC is
// not enabled, or the requester was unable to determine whether the remote
// server supports QUIC, it falls back to normal UDP.
//
// If message type reqT is to be signed, the key is initialized from m.signer.
// Otherwise it is set to a null signer.
func (m *Messenger) getFallbackRequester(reqT infra.MessageType) *pathingRequester {
	signer := infra.NullSigner
	return &pathingRequester{
		requester:       ctrl_msg.NewRequester(signer, infra.NullSigVerifier, m.dispatcher),
		addressRewriter: m.addressRewriter,
	}
}

func newTypeAssertErr(typeStr string, msg interface{}) error {
	return common.NewBasicError("Unable to type assert disp.Message", nil,
		"msg", msg, "type", typeStr)
}

// pathingRequester resolves the SCION path and constructs complete snet
// addresses.
type pathingRequester struct {
	requester       *ctrl_msg.Requester
	addressRewriter *AddressRewriter
}

func (pr *pathingRequester) Request(ctx context.Context, pld *ctrl.Pld,
	a net.Addr, downgradeToNotify bool) (*ctrl.Pld, error) {

	newAddr, _, err := pr.addressRewriter.RedirectToQUIC(ctx, a)
	if err != nil {
		return nil, err
	}
	logger := log.FromCtx(ctx)
	logger.Debug("Request could not be upgraded to QUIC, using UDP", "remote", newAddr)
	if downgradeToNotify {
		return nil, pr.requester.Notify(ctx, pld, newAddr)
	}
	pld, _, err = pr.requester.Request(ctx, pld, newAddr)
	return pld, err
}

func (pr *pathingRequester) Notify(ctx context.Context, pld *ctrl.Pld, a net.Addr) error {
	newAddr, _, err := pr.addressRewriter.RedirectToQUIC(ctx, a)
	if err != nil {
		return err
	}
	return pr.requester.Notify(ctx, pld, newAddr)
}

func (pr *pathingRequester) NotifyUnreliable(ctx context.Context, pld *ctrl.Pld, a net.Addr) error {
	newAddr, _, err := pr.addressRewriter.RedirectToQUIC(ctx, a)
	if err != nil {
		return err
	}
	return pr.requester.NotifyUnreliable(ctx, pld, newAddr)
}

// Validate checks that msg is one of the acceptable message types for SCION
// infra communication (listed in package level documentation), and returns the
// message type, the message (the inner proto.Cerealizable object), and an
// error (if one occurred).
func Validate(pld *ctrl.Pld) (infra.MessageType, proto.Cerealizable, error) {
	// XXX(scrye): For now, only the messages in the top comment of this
	// package are supported.
	switch pld.Which {
	case proto.CtrlPld_Which_ifid:
		return infra.IfId, pld.IfID, nil
	case proto.CtrlPld_Which_certMgmt:
		switch pld.CertMgmt.Which {
		default:
			return infra.None, nil,
				common.NewBasicError("Unsupported SignedPld.CtrlPld.CertMgmt.Xxx message type",
					nil, "capnp_which", pld.CertMgmt.Which)
		}
	case proto.CtrlPld_Which_pathMgmt:
		switch pld.PathMgmt.Which {
		case proto.PathMgmt_Which_hpSegReq:
			return infra.HPSegRequest, pld.PathMgmt.HPSegReq, nil
		case proto.PathMgmt_Which_hpSegReply:
			return infra.HPSegReply, pld.PathMgmt.HPSegReply, nil
		case proto.PathMgmt_Which_hpSegReg:
			return infra.HPSegReg, pld.PathMgmt.HPSegReg, nil
		case proto.PathMgmt_Which_hpCfgReq:
			return infra.HPCfgRequest, pld.PathMgmt.HPCfgReq, nil
		case proto.PathMgmt_Which_hpCfgReply:
			return infra.HPCfgReply, pld.PathMgmt.HPCfgReply, nil
		default:
			return infra.None, nil,
				common.NewBasicError("Unsupported SignedPld.CtrlPld.PathMgmt.Xxx message type",
					nil, "capnp_which", pld.PathMgmt.Which)
		}
	case proto.CtrlPld_Which_ack:
		return infra.Ack, pld.Ack, nil
	default:
		return infra.None, nil, common.NewBasicError("Unsupported SignedPld.Pld.Xxx message type",
			nil, "capnp_which", pld.Which)
	}
}

func extractPeer(peer net.Addr) (addr.IA, net.Addr) {
	switch v := peer.(type) {
	case *snet.SVCAddr:
		return v.IA, nil
	case *snet.UDPAddr:
		return v.IA, v.Host
	case *net.TCPAddr:
		return addr.IA{}, v
	default:
		return addr.IA{}, nil
	}
}
