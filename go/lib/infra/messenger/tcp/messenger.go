// Copyright 2020 Anapaya Systems
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

// Package tcp contains a tcp implementation of the messenger, it can be used
// for AS internal traffic.
package tcp

import (
	"context"
	"net"

	capnp "zombiezen.com/go/capnproto2"

	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/rpc"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/proto"
)

// NewClientMessenger creates a client messenger.
func NewClientMessenger(client Client) *Messenger {
	return &Messenger{
		Client: &client,
	}
}

// NewServerMessenger creates a TCP messenger with the given listen address.
// Note that only when calling `ListenAndServe` the messenger will actually
// handle requests.
func NewServerMessenger(listen *net.TCPAddr) *Messenger {
	ctx := context.Background()
	return &Messenger{
		Addr:    listen,
		Handler: messenger.NewStreamHandler(ctx, messenger.DefaultHandlerTimeout),
	}
}

// Messenger implements an intra-AS TCP messenger. Note that not all
// functionality is implemented.
type Messenger struct {
	// Addr is the listening address.
	Addr *net.TCPAddr
	// Handler is used to handle RPCs.
	Handler *messenger.QUICHandler
	// Client is used to request data from a remote.
	Client *Client

	listener net.Listener
}

func (m *Messenger) SendAck(ctx context.Context, msg *ack.Ack, a net.Addr, id uint64) error {
	panic("not implemented")
}

// GetTRC sends a cert_mgmt.TRCReq request to address a, blocks until it receives a
// reply and returns the reply.
func (m *Messenger) GetTRC(ctx context.Context, msg *cert_mgmt.TRCReq, a net.Addr,
	id uint64) (*cert_mgmt.TRC, error) {

	data := &ctrl.Data{ReqId: id, TraceId: tracing.IDFromCtx(ctx)}
	pld, err := ctrl.NewCertMgmtPld(msg, nil, data)
	if err != nil {
		return nil, err
	}
	logger := log.FromCtx(ctx)
	logger.Trace("[tcp-msger] Sending request", "req_type", infra.TRCRequest,
		"msg_id", id, "request", msg, "peer", a)
	replyCtrlPld, err := m.Client.Request(ctx, pld, a)
	if err != nil {
		return nil, serrors.WrapStr("[tcp-msger] request error", err, "req_type", infra.TRCRequest)
	}
	_, replyMsg, err := messenger.Validate(replyCtrlPld)
	if err != nil {
		return nil, serrors.WrapStr("[tcp-msger] reply validation failed", err)
	}
	switch reply := replyMsg.(type) {
	case *cert_mgmt.TRC:
		logger.Trace("[tcp-msger] Received reply", "req_id", id, "reply", reply)
		return reply, nil
	case *ack.Ack:
		return nil, &infra.Error{Message: reply}
	default:
		return nil, serrors.New("[tcp-msger] Type assertion failed",
			"msg", replyMsg, "type", "*cert_mgmt.TRC")
	}
}

// SendTRC sends a reliable cert_mgmt.TRC to address a.
func (m *Messenger) SendTRC(ctx context.Context, msg *cert_mgmt.TRC, a net.Addr, id uint64) error {
	panic("not implemented")
}

// GetCertChain sends a cert_mgmt.ChainReq to address a, blocks until it
// receives a reply and returns the reply.
func (m *Messenger) GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq, a net.Addr,
	id uint64) (*cert_mgmt.Chain, error) {

	logger := log.FromCtx(ctx)
	data := &ctrl.Data{ReqId: id, TraceId: tracing.IDFromCtx(ctx)}
	pld, err := ctrl.NewCertMgmtPld(msg, nil, data)
	if err != nil {
		return nil, err
	}
	logger.Trace("[tcp-msger] Sending request", "req_type", infra.ChainRequest,
		"msg_id", id, "request", msg, "peer", a)
	replyCtrlPld, err := m.Client.Request(ctx, pld, a)
	if err != nil {
		return nil, serrors.WrapStr("[tcp-msger] request error", err,
			"req_type", infra.ChainRequest)
	}
	_, replyMsg, err := messenger.Validate(replyCtrlPld)
	if err != nil {
		return nil, serrors.WrapStr("[tcp-msger] reply validation failed", err)
	}
	switch reply := replyMsg.(type) {
	case *cert_mgmt.Chain:
		logger.Trace("[tcp-msger] Received reply", "req_id", id, "reply", reply)
		return reply, nil
	case *ack.Ack:
		return nil, &infra.Error{Message: reply}
	default:
		return nil, serrors.New("[tcp-msger] Type assertion failed",
			"msg", replyMsg, "type", "*cert_mgmt.Chain")
	}
}

// SendCertChain sends a reliable cert_mgmt.Chain to address a.
func (m *Messenger) SendCertChain(ctx context.Context, msg *cert_mgmt.Chain, a net.Addr,
	id uint64) error {

	panic("not implemented")
}

// GetSegs asks the server at the remote address for the path segments that
// satisfy msg, and returns a verified reply.
func (m *Messenger) GetSegs(ctx context.Context, msg *path_mgmt.SegReq, a net.Addr,
	id uint64) (*path_mgmt.SegReply, error) {

	logger := log.FromCtx(ctx)
	data := &ctrl.Data{ReqId: id, TraceId: tracing.IDFromCtx(ctx)}
	pld, err := ctrl.NewPathMgmtPld(msg, nil, data)
	if err != nil {
		return nil, err
	}
	logger.Trace("[tcp-msger] Sending request", "req_type", infra.SegRequest,
		"msg_id", id, "request", msg, "peer", a)
	replyCtrlPld, err := m.Client.Request(ctx, pld, a)
	if err != nil {
		return nil, serrors.WrapStr("[tcp-msger] request error", err, "req_type", infra.SegRequest)
	}
	_, replyMsg, err := messenger.Validate(replyCtrlPld)
	if err != nil {
		return nil, serrors.WrapStr("[tcp-msger] reply validation failed", err)
	}
	switch reply := replyMsg.(type) {
	case *path_mgmt.SegReply:
		if err := reply.ParseRaw(); err != nil {
			return nil, serrors.WrapStr("[tcp-msger] failed to parse reply", err)
		}
		logger.Trace("[tcp-msger] Received reply", "req_id", id)
		return reply, nil
	case *ack.Ack:
		return nil, &infra.Error{Message: reply}
	default:
		return nil, serrors.New("[tcp-msger] Type assertion failed",
			"msg", replyMsg, "type", "*path_mgmt.SegReply")
	}
}

func (m *Messenger) AddHandler(msgType infra.MessageType, h infra.Handler) {
	m.Handler.Handle(msgType, h)
}

func (m *Messenger) ListenAndServe() {
	var err error
	m.listener, err = net.ListenTCP("tcp", m.Addr)
	if err != nil {
		log.Error("[tcp-msgr] Server listen error", "err", err)
		return
	}
	log.Info("Started listening TCP", "addr", m.Addr)
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			log.Error("[tcp-msgr] Listen error", "err", err)
			return
		}
		if err := m.handleConn(conn); err != nil {
			log.Warn("[tcp-msgr] Server handler exited with error", "err", err)
		}
	}
}

func (m *Messenger) CloseServer() error {
	return m.listener.Close()
}

func (m *Messenger) handleConn(conn net.Conn) error {
	rw := &replyWriter{conn: conn}
	msg, err := proto.SafeDecode(capnp.NewDecoder(conn))
	if err != nil {
		return err
	}
	request := &rpc.Request{
		Message: msg,
		Address: conn.RemoteAddr(),
	}
	go func() {
		defer log.LogPanicAndExit()
		m.Handler.ServeRPC(rw, request)
	}()
	return nil
}

type replyWriter struct {
	conn net.Conn
}

func (rw replyWriter) WriteReply(reply *rpc.Reply) error {
	if err := capnp.NewEncoder(rw.conn).Encode(reply.Message); err != nil {
		return err
	}
	if err := rw.conn.Close(); err != nil {
		return err
	}
	return nil
}

func (rw *replyWriter) Close() error {
	return rw.conn.Close()
}
