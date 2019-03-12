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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/ifid"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
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
	UpdateSigner(signer ctrl.Signer, types []MessageType)
	UpdateVerifier(verifier ctrl.SigVerifier)
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

type TrustStore interface {
	GetValidChain(ctx context.Context, ia addr.IA, source net.Addr) (*cert.Chain, error)
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
	NewSigner(s *proto.SignS, key common.RawBytes) ctrl.Signer
	NewSigVerifier() ctrl.SigVerifier
}

var (
	// NullSigner is a Signer that creates SignedPld's with no signature.
	NullSigner ctrl.Signer = &nullSigner{}
	// NullSigVerifier ignores signatures on all messages.
	NullSigVerifier ctrl.SigVerifier = &nullSigVerifier{}
)

var _ ctrl.Signer = (*nullSigner)(nil)

type nullSigner struct{}

func (*nullSigner) Sign(pld *ctrl.Pld) (*ctrl.SignedPld, error) {
	return ctrl.NewSignedPld(pld, nil, nil)
}

var _ ctrl.SigVerifier = (*nullSigVerifier)(nil)

type nullSigVerifier struct{}

func (*nullSigVerifier) Verify(context.Context, *ctrl.SignedPld) error {
	return nil
}
