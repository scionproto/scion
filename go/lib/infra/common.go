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

package infra

import (
	"context"
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/proto"
)

// Interface Transport wraps around low-level networking objects to provide
// reliable and unreliable delivery of network packets, together with
// context-aware networking that can be used to construct handlers with
// timeouts.
//
// Transport layers must be safe for concurrent use by multiple goroutines.
type Transport interface {
	// Send an unreliable message. Unreliable transport layers do not request
	// an ACK. For reliable transport layers, this is the same as SendMsgTo.
	SendUnreliableMsgTo(context.Context, common.RawBytes, net.Addr) error
	// Send a reliable message. Unreliable transport layers block here waiting
	// for the message to be ACK'd. Reliable transport layers return
	// immediately.
	SendMsgTo(context.Context, common.RawBytes, net.Addr) error
	// Receive a message.
	RecvFrom(context.Context) (common.RawBytes, net.Addr, error)
	// Clean up.
	Close(context.Context) error
}

// Interface Handler is implemented by objects that can handle a request coming
// from a remote SCION network node.
type Handler interface {
	Handle(*Request)
}

// Constructs a handler for request r. Handle() can be called on the
// resulting object to process the message.
type HandlerFunc func(r *Request)

func (f HandlerFunc) Handle(r *Request) {
	f(r)
}

// Request describes an object received from the network that is not part of an
// exchange initiated by the local node. A Request includes its associated
// context.
type Request struct {
	// Message is the inner proto.Cerealizable message, as supported by
	// messenger.Messenger (e.g., a *cert_mgmt.ChainReq). For information about
	// possible messages, see the package documentation for that package.
	Message proto.Cerealizable
	// FullMessage is the top-level SignedCtrlPld message read from the wire
	FullMessage proto.Cerealizable
	// Peer is the node that sent this request
	Peer net.Addr

	ID uint64
	// ctx is a server context, used in handlers when receiving messages from
	// the network.
	ctx context.Context
}

func NewRequest(ctx context.Context, msg, fullMsg proto.Cerealizable, peer net.Addr,
	id uint64) *Request {

	return &Request{
		Message:     msg,
		FullMessage: fullMsg,
		Peer:        peer,
		ctx:         ctx,
		ID:          id,
	}
}

// Context returns the request's context.
func (r *Request) Context() context.Context {
	return r.ctx
}

var (
	// messengerContextKey is a context key. It can be used in SCION infra
	// request handlers to access the messaging layer the message arrived on.
	messengerContextKey = &contextKey{"infra-messenger"}
)

type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "infra/messenger context value " + k.name
}

func NewContextWithMessenger(ctx context.Context, msger Messenger) context.Context {
	return context.WithValue(ctx, messengerContextKey, msger)
}

type MessageType int

const (
	None MessageType = iota
	TRC
	TRCRequest
	Chain
	ChainRequest
	PathSegmentRequest
	PathSegmentReply
	ChainIssueRequest
	ChainIssueReply
)

func (mt MessageType) String() string {
	switch mt {
	case None:
		return "None"
	case ChainRequest:
		return "ChainRequest"
	case Chain:
		return "Chain"
	case TRCRequest:
		return "TRCRequest"
	case TRC:
		return "TRC"
	case PathSegmentRequest:
		return "PathSegmentRequest"
	case PathSegmentReply:
		return "PathSegmentReply"
	case ChainIssueRequest:
		return "ChainIssueRequest"
	case ChainIssueReply:
		return "ChainIssueReply"
	default:
		return fmt.Sprintf("Unknown (%d)", mt)
	}
}

type Messenger interface {
	GetTRC(ctx context.Context, msg *cert_mgmt.TRCReq, a net.Addr,
		id uint64) (*cert_mgmt.TRC, error)
	SendTRC(ctx context.Context, msg *cert_mgmt.TRC, a net.Addr, id uint64) error
	GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq, a net.Addr,
		id uint64) (*cert_mgmt.Chain, error)
	SendCertChain(ctx context.Context, msg *cert_mgmt.Chain, a net.Addr, id uint64) error
	GetPathSegs(ctx context.Context, msg *path_mgmt.SegReq, a net.Addr,
		id uint64) (*path_mgmt.SegReply, error)
	RequestChainIssue(ctx context.Context, msg *cert_mgmt.ChainIssReq, a net.Addr,
		id uint64) (*cert_mgmt.ChainIssRep, error)
	SendChainIssueReply(ctx context.Context, msg *cert_mgmt.ChainIssRep, a net.Addr,
		id uint64) error
	AddHandler(msgType MessageType, h Handler)
	ListenAndServe()
	CloseServer() error
}

func MessengerFromContext(ctx context.Context) (Messenger, bool) {
	msger, ok := ctx.Value(messengerContextKey).(Messenger)
	return msger, ok
}

type TrustStore interface {
	GetValidChain(ctx context.Context, ia addr.IA, trail ...addr.ISD) (*cert.Chain, error)
	GetValidTRC(ctx context.Context, isd addr.ISD, trail ...addr.ISD) (*trc.TRC, error)
	GetChain(ctx context.Context, ia addr.IA, version uint64) (*cert.Chain, error)
	GetTRC(ctx context.Context, isd addr.ISD, version uint64) (*trc.TRC, error)
	NewTRCReqHandler(recurseAllowed bool) Handler
	NewChainReqHandler(recurseAllowed bool) Handler
	SetMessenger(msger Messenger)
}
