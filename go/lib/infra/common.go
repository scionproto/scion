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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/ifid"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
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

// ResourceHealth indicates the health of a resource. A resource could for example be a database.
// The resource health can be added to a handler, so that the handler only replies if all it's
// resources are healthy.
type ResourceHealth interface {
	// Name returns the name of this resource.
	Name() string
	// IsHealthy returns whether the resource is considered healthy currently.
	// This method must not be blocking and should have the result cached and return ~immediately.
	IsHealthy() bool
}

// NewResourceAwareHandler creates a decorated handler that calls the underlying handler if all
// resources are healthy, otherwise it replies with an error message.
func NewResourceAwareHandler(handler Handler, resources ...ResourceHealth) Handler {
	return HandlerFunc(func(r *Request) *HandlerResult {
		ctx := r.Context()
		for _, resource := range resources {
			if !resource.IsHealthy() {
				logger := log.FromCtx(ctx)
				rwriter, ok := ResponseWriterFromContext(ctx)
				if !ok {
					logger.Error("No response writer found")
					return MetricsErrInternal
				}
				logger.Info("Resource not healthy, can't handle request",
					"resource", resource.Name())
				rwriter.SendAckReply(ctx, &ack.Ack{
					Err:     proto.Ack_ErrCode_reject,
					ErrDesc: fmt.Sprintf("Resource %s not healthy", resource.Name()),
				})
				return MetricsErrInternal
			}
		}
		return handler.Handle(r)
	})
}

type Messenger interface {
	SendAck(ctx context.Context, msg *ack.Ack, a net.Addr, id uint64) error
	// SendIfId sends a reliable ifid.IFID to address a.
	SendIfId(ctx context.Context, msg *ifid.IFID, a net.Addr, id uint64) error
	SendHPSegReg(ctx context.Context, msg *path_mgmt.HPSegReg, a net.Addr, id uint64) error
	GetHPSegs(ctx context.Context, msg *path_mgmt.HPSegReq, a net.Addr,
		id uint64) (*path_mgmt.HPSegReply, error)
	SendHPSegReply(ctx context.Context, msg *path_mgmt.HPSegReply, a net.Addr, id uint64) error
	GetHPCfgs(ctx context.Context, msg *path_mgmt.HPCfgReq, a net.Addr,
		id uint64) (*path_mgmt.HPCfgReply, error)
	SendHPCfgReply(ctx context.Context, msg *path_mgmt.HPCfgReply, a net.Addr, id uint64) error
	AddHandler(msgType MessageType, h Handler)
	ListenAndServe()
	CloseServer() error
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

// SignatureTimestampRange configures the range a signature timestamp is
// considered valid. This allows for small clock drifts in the network.
type SignatureTimestampRange struct {
	// MaxPldAge determines the maximum age of a control payload signature.
	MaxPldAge time.Duration
	// MaxInFuture determines the maximum time a timestamp may be in the future.
	MaxInFuture time.Duration
}

type LegacyVerifier interface {
	ctrl.Verifier
	Verifier
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

var (
	// NullSigner is a Signer that creates SignedPld's with no signature.
	NullSigner ctrl.Signer = nullSigner{}
	// NullSigVerifier ignores signatures on all messages.
	NullSigVerifier LegacyVerifier = nullSigVerifier{}
)

var _ ctrl.Signer = nullSigner{}

type nullSigner struct{}

func (nullSigner) SignLegacy(context.Context, []byte) (*proto.SignS, error) {
	return &proto.SignS{}, nil
}

var _ Verifier = nullSigVerifier{}

type nullSigVerifier struct{}

func (nullSigVerifier) Verify(_ context.Context, msg *cryptopb.SignedMessage,
	_ ...[]byte) (*signed.Message, error) {

	hdr, err := signed.ExtractUnverifiedHeader(msg)
	if err != nil {
		return nil, err
	}
	body, err := signed.ExtractUnverifiedBody(msg)
	if err != nil {
		return nil, err
	}
	return &signed.Message{
		Header: signed.Header(*hdr),
		Body:   body,
	}, nil
}

func (nullSigVerifier) VerifyPld(_ context.Context, spld *ctrl.SignedPld) (*ctrl.Pld, error) {
	return spld.UnsafePld()
}

func (nullSigVerifier) WithServer(_ net.Addr) Verifier {
	return nullSigVerifier{}
}

func (nullSigVerifier) WithIA(_ addr.IA) Verifier {
	return nullSigVerifier{}
}
