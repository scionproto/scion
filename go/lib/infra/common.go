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

package infra

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/proto"
)

const (
	// DefaultRPCTimeout is the default silent time SCION RPC Clients will wait
	// for before declaring a timeout. Most RPCs will be subject to an
	// additional context, and the timeout will be the minimum value allowed by
	// the context and this timeout. RPC clients are free to use a different
	// timeout if they have special requirements.
	DefaultRPCTimeout time.Duration = 10 * time.Second
)

// Handler is implemented by objects that can handle a request coming
// from a remote SCION network node.
type Handler interface {
	Handle(*Request) *HandlerResult
}

// Constructs a handler for request r. Handle() can be called on the
// resulting object to process the message.
type HandlerFunc func(r *Request) *HandlerResult

func (f HandlerFunc) Handle(r *Request) *HandlerResult {
	return f(r)
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
	// ID is the CtrlPld top-level ID.
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
	// responseWriterKey is a context key. It can be used in SCION infra
	// request handlers to reply to a remote request.
	responseWriterContextKey = &contextKey{"response-writer"}
)

type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "infra/messenger context value " + k.name
}

func NewContextWithResponseWriter(ctx context.Context, rw ResponseWriter) context.Context {
	return context.WithValue(ctx, responseWriterContextKey, rw)
}

type MessageType int

const (
	None MessageType = iota
	IfId
	Ack
	HPSegReg
	HPSegRequest
	HPSegReply
	HPCfgRequest
	HPCfgReply
)

func (mt MessageType) String() string {
	switch mt {
	case None:
		return "None"
	case IfId:
		return "IfId"
	case Ack:
		return "Ack"
	case HPSegReg:
		return "HPSegReg"
	case HPSegRequest:
		return "HPSegRequest"
	case HPSegReply:
		return "HPSegReply"
	case HPCfgRequest:
		return "HPCfgRequest"
	case HPCfgReply:
		return "HPCfgReply"
	default:
		return fmt.Sprintf("Unknown (%d)", mt)
	}
}

// MetricLabel returns the label for metrics for a given message type.
// The postfix for requests is always "req" and for replies and push messages it is always "push".
func (mt MessageType) MetricLabel() string {
	switch mt {
	case None:
		return "none"
	case IfId:
		return "ifid_push"
	case Ack:
		return "ack_push"
	case HPSegReg:
		return "hp_seg_reg_push"
	case HPSegRequest:
		return "hp_seg_req"
	case HPSegReply:
		return "hp_seg_push"
	case HPCfgRequest:
		return "hp_cfg_req"
	case HPCfgReply:
		return "hp_cfg_push"
	default:
		return "unknown_mt"
	}
}

type ResponseWriter interface {
	SendAckReply(ctx context.Context, msg *ack.Ack) error
	SendHPSegReply(ctx context.Context, msg *path_mgmt.HPSegReply) error
	SendHPCfgReply(ctx context.Context, msg *path_mgmt.HPCfgReply) error
}

func ResponseWriterFromContext(ctx context.Context) (ResponseWriter, bool) {
	if ctx == nil {
		return nil, false
	}
	rw, ok := ctx.Value(responseWriterContextKey).(ResponseWriter)
	return rw, ok
}

var _ error = (*Error)(nil)

type Error struct {
	Message *ack.Ack
}

func (e *Error) Error() string {
	return fmt.Sprintf("rpc: error from remote: %q", e.Message.ErrDesc)
}

// Verifier is used to verify payloads signed with control-plane PKI
// certificates.
type Verifier interface {
	seg.Verifier
	// WithServer returns a verifier that fetches the necessary crypto
	// objects from the specified server.
	WithServer(server net.Addr) Verifier
	// WithIA returns a verifier that only accepts signatures from the
	// specified IA.
	WithIA(ia addr.IA) Verifier
}
