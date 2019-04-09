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
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/ifid"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
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
	TRC
	TRCRequest
	Chain
	ChainRequest
	IfId
	IfStateInfos
	IfStateReq
	Seg
	SegChangesReq
	SegChangesReply
	SegChangesIdReq
	SegChangesIdReply
	SegReg
	SegRequest
	SegReply
	SegRev
	SegSync
	ChainIssueRequest
	ChainIssueReply
	Ack
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
	case IfId:
		return "IfId"
	case IfStateInfos:
		return "IfStateInfos"
	case IfStateReq:
		return "IfStateReq"
	case Seg:
		return "Seg"
	case SegChangesReq:
		return "SegChangesReq"
	case SegChangesReply:
		return "SegChangesReply"
	case SegChangesIdReq:
		return "SegChangesIdReq"
	case SegChangesIdReply:
		return "SegChangesIdReply"
	case SegReg:
		return "SegReg"
	case SegRequest:
		return "SegRequest"
	case SegReply:
		return "SegReply"
	case SegRev:
		return "SegRev"
	case SegSync:
		return "SegSync"
	case ChainIssueRequest:
		return "ChainIssueRequest"
	case ChainIssueReply:
		return "ChainIssueReply"
	case Ack:
		return "Ack"
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
	case ChainRequest:
		return "chain_req"
	case Chain:
		return "chain_push"
	case TRCRequest:
		return "trc_req"
	case TRC:
		return "trc_push"
	case IfId:
		return "ifid_push"
	case IfStateInfos:
		return "if_info_push"
	case IfStateReq:
		return "if_info_req"
	case Seg:
		return "pathseg_push"
	case SegChangesReq:
		return "seg_changes_req"
	case SegChangesReply:
		return "seg_changes_push"
	case SegChangesIdReq:
		return "seg_changes_id_req"
	case SegChangesIdReply:
		return "seg_changes_id_push"
	case SegReg:
		return "seg_reg_push"
	case SegRequest:
		return "seg_req"
	case SegReply:
		return "seg_push"
	case SegRev:
		return "seg_rev_push"
	case SegSync:
		return "seg_sync_push"
	case ChainIssueRequest:
		return "chain_issue_req"
	case ChainIssueReply:
		return "chain_issue_push"
	case Ack:
		return "ack_push"
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
				logger.Warn("Resource not healthy, can't handle request",
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
	// GetTRC sends a cert_mgmt.TRCReq request to address a, blocks until it receives a
	// reply and returns the reply.
	GetTRC(ctx context.Context, msg *cert_mgmt.TRCReq, a net.Addr,
		id uint64) (*cert_mgmt.TRC, error)
	// SendTRC sends a reliable cert_mgmt.TRC to address a.
	SendTRC(ctx context.Context, msg *cert_mgmt.TRC, a net.Addr, id uint64) error
	// GetCertChain sends a cert_mgmt.ChainReq to address a, blocks until it
	// receives a reply and returns the reply.
	GetCertChain(ctx context.Context, msg *cert_mgmt.ChainReq, a net.Addr,
		id uint64) (*cert_mgmt.Chain, error)
	// SendCertChain sends a reliable cert_mgmt.Chain to address a.
	SendCertChain(ctx context.Context, msg *cert_mgmt.Chain, a net.Addr, id uint64) error
	// SendIfId sends a reliable ifid.IFID to address a.
	SendIfId(ctx context.Context, msg *ifid.IFID, a net.Addr, id uint64) error
	// SendIfStateInfos sends a reliable path_mgmt.IfStateInfos to address a.
	SendIfStateInfos(ctx context.Context, msg *path_mgmt.IFStateInfos, a net.Addr, id uint64) error
	// SendSeg sends a reliable seg.Pathsegment to a.
	SendSeg(ctx context.Context, msg *seg.PathSegment, a net.Addr, id uint64) error
	// GetSegs asks the server at the remote address for the path segments that
	// satisfy msg, and returns a verified reply.
	GetSegs(ctx context.Context, msg *path_mgmt.SegReq, a net.Addr,
		id uint64) (*path_mgmt.SegReply, error)
	// SendSegReply sends a reliable path_mgmt.SegReply to address a.
	SendSegReply(ctx context.Context, msg *path_mgmt.SegReply, a net.Addr, id uint64) error
	// SendSegSync sends a reliable path_mgmt.SegSync to address a.
	SendSegSync(ctx context.Context, msg *path_mgmt.SegSync, a net.Addr, id uint64) error
	GetSegChangesIds(ctx context.Context, msg *path_mgmt.SegChangesIdReq,
		a net.Addr, id uint64) (*path_mgmt.SegChangesIdReply, error)
	SendSegChangesIdReply(ctx context.Context,
		msg *path_mgmt.SegChangesIdReply, a net.Addr, id uint64) error
	GetSegChanges(ctx context.Context, msg *path_mgmt.SegChangesReq,
		a net.Addr, id uint64) (*path_mgmt.SegChangesReply, error)
	SendSegChangesReply(ctx context.Context,
		msg *path_mgmt.SegChangesReply, a net.Addr, id uint64) error
	RequestChainIssue(ctx context.Context, msg *cert_mgmt.ChainIssReq, a net.Addr,
		id uint64) (*cert_mgmt.ChainIssRep, error)
	SendChainIssueReply(ctx context.Context, msg *cert_mgmt.ChainIssRep, a net.Addr,
		id uint64) error
	UpdateSigner(signer Signer, types []MessageType)
	UpdateVerifier(verifier Verifier)
	AddHandler(msgType MessageType, h Handler)
	ListenAndServe()
	CloseServer() error
}

type ResponseWriter interface {
	SendAckReply(ctx context.Context, msg *ack.Ack) error
	SendTRCReply(ctx context.Context, msg *cert_mgmt.TRC) error
	SendCertChainReply(ctx context.Context, msg *cert_mgmt.Chain) error
	SendChainIssueReply(ctx context.Context, msg *cert_mgmt.ChainIssRep) error
	SendSegReply(ctx context.Context, msg *path_mgmt.SegReply) error
}

func ResponseWriterFromContext(ctx context.Context) (ResponseWriter, bool) {
	rw, ok := ctx.Value(responseWriterContextKey).(ResponseWriter)
	return rw, ok
}

var _ error = (*Error)(nil)

type Error struct {
	Message *ack.Ack
}

func (e *Error) Error() string {
	return e.Message.ErrDesc
}

// SignerMeta indicates what signature metadata the signer uses as a basis
// when creating signatures.
type SignerMeta struct {
	// Src is the signature source, containing the certificate chain version.
	Src ctrl.SignSrcDef
	// ExpTime indicates the expiration time of the certificate chain.
	ExpTime time.Time
	// Algo indicates the signing algorithm.
	Algo string
}

// Signer is a signer leveraging the control-plane PKI certificates.
type Signer interface {
	ctrl.Signer
	Meta() SignerMeta
}

// Verifier is used to verify payloads signed with control-plane PKI
// certificates.
type Verifier interface {
	ctrl.Verifier
	Verify(ctx context.Context, msg common.RawBytes, sign *proto.SignS) error
	// WithServer returns a verifier that fetches the necessary crypto
	// objects from the specified server.
	WithServer(server net.Addr) Verifier
	// WithIA returns a verifier that only accepts signatures from the
	// specified AS. Zero values in the ISD-AS pair are considered a wild
	// card.
	WithIA(ia addr.IA) Verifier
	// WithSrc returns a verifier that is bound to the specified source.
	// It verifies against the specified source, and not the value
	// provided by the sign meta data.
	WithSrc(src ctrl.SignSrcDef) Verifier
}

type TrustStore interface {
	GetValidChain(ctx context.Context, ia addr.IA, ver uint64, source net.Addr) (*cert.Chain, error)
	GetValidTRC(ctx context.Context, isd addr.ISD, source net.Addr) (*trc.TRC, error)
	GetValidCachedTRC(ctx context.Context, isd addr.ISD) (*trc.TRC, error)
	GetChain(ctx context.Context, ia addr.IA, version uint64) (*cert.Chain, error)
	GetTRC(ctx context.Context, isd addr.ISD, version uint64) (*trc.TRC, error)
	NewTRCReqHandler(recurseAllowed bool) Handler
	NewChainReqHandler(recurseAllowed bool) Handler
	SetMessenger(msger Messenger)
	MsgVerificationFactory
}

type MsgVerificationFactory interface {
	NewSigner(key common.RawBytes, meta SignerMeta) (Signer, error)
	NewVerifier() Verifier
}

var (
	// NullSigner is a Signer that creates SignedPld's with no signature.
	NullSigner Signer = nullSigner{}
	// NullSigVerifier ignores signatures on all messages.
	NullSigVerifier Verifier = nullSigVerifier{}
)

var _ Signer = nullSigner{}

type nullSigner struct{}

func (nullSigner) Sign(raw common.RawBytes) (*proto.SignS, error) {
	return &proto.SignS{}, nil
}

func (nullSigner) Meta() SignerMeta {
	return SignerMeta{}
}

var _ Verifier = nullSigVerifier{}

type nullSigVerifier struct{}

func (nullSigVerifier) Verify(_ context.Context, _ common.RawBytes, _ *proto.SignS) error {
	return nil
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

func (nullSigVerifier) WithSrc(_ ctrl.SignSrcDef) Verifier {
	return nullSigVerifier{}
}
