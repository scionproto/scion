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

package handler

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/cs/trust/internal/metrics"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/renewal"
	"github.com/scionproto/scion/go/proto"
)

// RenewalRequestVerifier verifies the incoming chain renewal request.
type RenewalRequestVerifier interface {
	VerifyChainRenewalRequest(*cert_mgmt.ChainRenewalRequest,
		[][]*x509.Certificate) (*x509.CertificateRequest, error)
}

// RenewalRequestVerifierFunc allows a func to implement the interface
type RenewalRequestVerifierFunc func(*cert_mgmt.ChainRenewalRequest,
	[][]*x509.Certificate) (*x509.CertificateRequest, error)

func (f RenewalRequestVerifierFunc) VerifyChainRenewalRequest(req *cert_mgmt.ChainRenewalRequest,
	chains [][]*x509.Certificate) (*x509.CertificateRequest, error) {
	return f(req, chains)
}

// ChainBuilder creates a chain for the given CSR.
type ChainBuilder interface {
	CreateChain(context.Context, *x509.CertificateRequest) ([]*x509.Certificate, error)
}

// ChainRenewalRequest is a handler for chain renewal request messages.
type ChainRenewalRequest struct {
	Verifier     RenewalRequestVerifier
	ChainBuilder ChainBuilder
	Signer       ctrl.Signer
	DB           renewal.DB
	IA           addr.IA
}

// Handle handles a chain renewal request message.
func (h ChainRenewalRequest) Handle(req *infra.Request) *infra.HandlerResult {
	l := metrics.HandlerLabels{ReqType: metrics.ChainRenewalReq, Client: infra.PromSrcUnknown}
	if req == nil {
		log.Error("[trust:ChainRenewalReq] Request is nil")
		metrics.Handler.Request(l.WithResult(metrics.ErrInternal)).Inc()
		return infra.MetricsErrInternal
	}
	l.Client = metrics.PeerToLabel(req.Peer, h.IA)

	span, ctx := opentracing.StartSpanFromContext(req.Context(),
		"trusthandler.chain_renewal_request")
	defer span.Finish()
	logger := log.FromCtx(ctx)

	renewalReq, ok := req.Message.(*cert_mgmt.ChainRenewalRequest)
	if !ok {
		logger.Error("[trust:ChainRenewalReq] Wrong message type,"+
			" expected cert_mgmt.ChainRenewalRequest",
			"msg", req.Message, "type", common.TypeOf(req.Message))
		setHandlerMetric(span, l.WithResult(metrics.ErrInternal), errWrongMsgType)
		return infra.MetricsErrInternal
	}

	logger.Debug("[trust:ChainRenewalReq] Received request",
		"chainRenewalReq", renewalReq, "peer", req.Peer)
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Error("[trust:ChainRenewalReq] Unable to service request, no ResponseWriter found")
		setHandlerMetric(span, l.WithResult(metrics.ErrInternal), errNoResponseWriter)
		return infra.MetricsErrInternal
	}
	sendAck := messenger.SendAckHelper(ctx, rw)
	src, err := ctrl.NewX509SignSrc(renewalReq.Signature.Src)
	if err != nil {
		logger.Error("[trust:ChainRenewalReq] Unable to service request, invalid signature src",
			"err", err)
		setHandlerMetric(span, l.WithResult(metrics.ErrValidate),
			serrors.New("invalid req signature"))
		sendAck(proto.Ack_ErrCode_reject, "invalid signature")
		return infra.MetricsErrInvalid
	}
	chains, err := h.DB.ClientChains(ctx, trust.ChainQuery{
		IA:           src.IA,
		SubjectKeyID: src.SubjectKeyID,
		Date:         time.Now(),
	})
	if err != nil {
		logger.Error("[trust:ChainRenewalReq] Failed to load client chains", "err", err)
		setHandlerMetric(span, l.WithResult(metrics.ErrDB), err)
		sendAck(proto.Ack_ErrCode_retry, "db error")
		return infra.MetricsErrTrustDB(err)
	}
	if len(chains) == 0 {
		logger.Error("[trust:ChainRenewalReq] No client chains found")
		setHandlerMetric(span, l.WithResult(metrics.ErrNotFound), err)
		sendAck(proto.Ack_ErrCode_reject, "not client")
		return infra.MetricsErrInvalid
	}
	csr, err := h.Verifier.VerifyChainRenewalRequest(renewalReq, chains)
	if err != nil {
		logger.Error("[trust:ChainRenewalReq] Failed to verify request", "err", err)
		setHandlerMetric(span, l.WithResult(metrics.ErrVerify), err)
		sendAck(proto.Ack_ErrCode_reject, "invalid request")
		return infra.MetricsErrInvalid
	}
	chain, err := h.ChainBuilder.CreateChain(ctx, csr)
	if err != nil {
		logger.Error("[trust:ChainRenewalReq] Failed to sign request", "err", err)
		setHandlerMetric(span, l.WithResult(metrics.ErrInternal), err)
		sendAck(proto.Ack_ErrCode_retry, "failed to sign")
		return infra.MetricsErrInternal
	}
	if _, err := h.DB.InsertClientChain(ctx, chain); err != nil {
		logger.Error("[trust:ChainRenewalReq] Failed to store new chain", "err", err)
		setHandlerMetric(span, l.WithResult(metrics.ErrDB), err)
		sendAck(proto.Ack_ErrCode_retry, "db error")
		return infra.MetricsErrTrustDB(err)
	}
	msg := append(append([]byte(nil), chain[0].Raw...), chain[1].Raw...)
	signature, err := h.Signer.Sign(ctx, msg)
	if err != nil {
		logger.Error("[trust:ChainRenewalReq] Failed to sign reply", "err", err)
		setHandlerMetric(span, l.WithResult(metrics.ErrInternal), err)
		sendAck(proto.Ack_ErrCode_reject, "signer error")
		return infra.MetricsErrInternal
	}
	reply := &cert_mgmt.ChainRenewalReply{
		RawChain:  msg,
		Signature: signature,
	}
	if err := rw.SendChainRenewalReply(ctx, reply); err != nil {
		logger.Error("[trust:ChainRenewalReq] Failed to send new chain", "err", err)
		setHandlerMetric(span, l.WithResult(metrics.ErrTransmit), err)
		return infra.MetricsErrMsger(err)
	}
	logger.Info("[trust:ChainRenewalReq] issued new chain",
		"ia", src.IA, "subject_key_id", chain[0].SubjectKeyId,
		"validity", cppki.Validity{NotBefore: chain[0].NotBefore, NotAfter: chain[0].NotAfter})
	setHandlerMetric(span, l.WithResult(metrics.Success), nil)
	return infra.MetricsResultOk
}
