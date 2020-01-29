// Copyright 2019 Anapaya Systems
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

package trust

import (
	"context"
	"errors"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/decoded"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/metrics"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

// AckNotFound is sent as the error description if the crypto material is
// not found.
const AckNotFound string = "not found"

// chainReqHandler contains the state of a handler for a specific Certificate
// Chain Request message, received via the Messenger's ListenAndServe method.
type chainReqHandler struct {
	request  *infra.Request
	provider CryptoProvider
	ia       addr.IA
}

func (h *chainReqHandler) Handle() *infra.HandlerResult {
	l := metrics.HandlerLabels{ReqType: metrics.ChainReq, Client: infra.PromSrcUnknown}
	if h.request == nil {
		log.Error("[TrustStore:chainReqHandler] Request is nil")
		metrics.Handler.Request(l.WithResult(metrics.ErrInternal)).Inc()
		return infra.MetricsErrInternal
	}
	l.Client = peerToLabel(h.request.Peer, h.ia)

	ctx := metrics.CtxWith(h.request.Context(), metrics.ChainReq)
	logger := log.FromCtx(ctx)
	chainReq, ok := h.request.Message.(*cert_mgmt.ChainReq)
	if !ok {
		logger.Error("[TrustStore:chainReqHandler] wrong message type, expected cert_mgmt.ChainReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		metrics.Handler.Request(l.WithResult(metrics.ErrInternal)).Inc()
		return infra.MetricsErrInternal
	}
	logger.Debug("[TrustStore:chainReqHandler] Received request", "chainReq", chainReq,
		"peer", h.request.Peer)
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Warn("[TrustStore:chainReqHandler] Unable to service request, " +
			"no ResponseWriter found")
		metrics.Handler.Request(l.WithResult(metrics.ErrInternal)).Inc()
		return infra.MetricsErrInternal
	}
	sendAck := messenger.SendAckHelper(ctx, rw)
	raw, err := h.provider.GetRawChain(ctx,
		ChainID{IA: chainReq.IA(), Version: chainReq.Version},
		infra.ChainOpts{
			TrustStoreOpts: infra.TrustStoreOpts{Client: h.request.Peer},
			AllowInactive:  true,
		},
	)
	if err != nil {
		logger.Error("[TrustStore:chainReqHandler] Unable to retrieve chain", "err", err)
		sendAck(proto.Ack_ErrCode_reject, AckNotFound)
		metrics.Handler.Request(l.WithResult(metrics.ErrInternal)).Inc()
		return infra.MetricsErrTrustStore(err)
	}
	reply := &cert_mgmt.Chain{
		RawChain: raw,
	}
	if err = rw.SendCertChainReply(ctx, reply); err != nil {
		logger.Error("[TrustStore:chainReqHandler] Messenger API error", "err", err)
		metrics.Handler.Request(l.WithResult(metrics.ErrTransmit)).Inc()
		return infra.MetricsErrMsger(err)
	}
	logger.Debug("[TrustStore:chainReqHandler] Replied with chain",
		"ia", chainReq.IA(), "version", chainReq.Version, "peer", h.request.Peer)
	metrics.Handler.Request(l.WithResult(metrics.Success)).Inc()
	return infra.MetricsResultOk
}

// trcReqHandler contains the state of a handler for a specific TRC Request
// message, received via the Messenger's ListenAndServe method.
type trcReqHandler struct {
	request  *infra.Request
	provider CryptoProvider
	ia       addr.IA
}

func (h *trcReqHandler) Handle() *infra.HandlerResult {
	l := metrics.HandlerLabels{ReqType: metrics.TRCReq, Client: infra.PromSrcUnknown}
	if h.request == nil {
		log.Error("[TrustStore:trcReqHandler] Request is nil")
		return infra.MetricsErrInternal
	}
	l.Client = peerToLabel(h.request.Peer, h.ia)

	ctx := metrics.CtxWith(h.request.Context(), metrics.TRCReq)
	logger := log.FromCtx(ctx)
	trcReq, ok := h.request.Message.(*cert_mgmt.TRCReq)
	if !ok {
		logger.Error("[TrustStore:trcReqHandler] wrong message type, expected cert_mgmt.TRCReq",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		metrics.Handler.Request(l.WithResult(metrics.ErrInternal)).Inc()
		return infra.MetricsErrInternal
	}
	logger.Debug("[TrustStore:trcReqHandler] Received request", "trcReq", trcReq,
		"peer", h.request.Peer)
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Error("[TrustStore:trcReqHandler] Unable to service request," +
			" no ResponseWriter found")
		metrics.Handler.Request(l.WithResult(metrics.ErrInternal)).Inc()
		return infra.MetricsErrInternal
	}
	sendAck := messenger.SendAckHelper(ctx, rw)
	raw, err := h.provider.GetRawTRC(ctx,
		TRCID{ISD: trcReq.ISD, Version: trcReq.Version},
		infra.TRCOpts{
			TrustStoreOpts: infra.TrustStoreOpts{Client: h.request.Peer},
			AllowInactive:  true,
		},
	)
	if err != nil {
		logger.Error("[TrustStore:trcReqHandler] Unable to retrieve TRC", "err", err)
		sendAck(proto.Ack_ErrCode_reject, AckNotFound)
		metrics.Handler.Request(l.WithResult(metrics.ErrInternal)).Inc()
		return infra.MetricsErrTrustStore(err)
	}
	reply := &cert_mgmt.TRC{
		RawTRC: raw,
	}
	if err := rw.SendTRCReply(ctx, reply); err != nil {
		logger.Error("[TrustStore:trcReqHandler] Messenger error", "err", err)
		metrics.Handler.Request(l.WithResult(metrics.ErrTransmit)).Inc()
		return infra.MetricsErrMsger(err)
	}
	logger.Debug("[TrustStore:trcReqHandler] Replied with TRC", "isd", trcReq.ISD,
		"version", trcReq.Version, "peer", h.request.Peer)
	metrics.Handler.Request(l.WithResult(metrics.Success)).Inc()
	return infra.MetricsResultOk
}

type chainPushHandler struct {
	request  *infra.Request
	provider CryptoProvider
	inserter Inserter
	ia       addr.IA
}

func (h *chainPushHandler) Handle() *infra.HandlerResult {
	l := metrics.HandlerLabels{ReqType: metrics.ChainPush, Client: infra.PromSrcUnknown}
	if h.request == nil {
		log.Error("[TrustStore:chainPushHandler] Request is nil")
		return infra.MetricsErrInternal
	}
	l.Client = peerToLabel(h.request.Peer, h.ia)

	ctx := metrics.CtxWith(h.request.Context(), metrics.ChainReq)
	logger := log.FromCtx(ctx)
	chainPush, ok := h.request.Message.(*cert_mgmt.Chain)
	if !ok {
		logger.Error("[TrustStore:chainPushHandler] Wrong message type, expected cert_mgmt.Chain",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		metrics.Handler.Request(l.WithResult(metrics.ErrInternal)).Inc()
		return infra.MetricsErrInternal
	}
	logger.Trace("[TrustStore:chainPushHandler] Received push", "chainPush", chainPush,
		"peer", h.request.Peer)
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Warn(
			"[TrustStore:chainPushHandler] Unable to service request, no ResponseWriter found")
		metrics.Handler.Request(l.WithResult(metrics.ErrInternal)).Inc()
		return infra.MetricsErrInternal
	}
	sendAck := messenger.SendAckHelper(ctx, rw)

	dec, err := decoded.DecodeChain(chainPush.RawChain)
	if err != nil {
		logger.Error("[TrustStore:chainPushHandler] Unable to parse chain from push", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		metrics.Handler.Request(l.WithResult(metrics.ErrParse)).Inc()
		return infra.MetricsErrInvalid
	}
	err = h.inserter.InsertChain(ctx, dec, newTRCGetter(h.provider, h.request.Peer))
	switch {
	case err == nil:
		sendAck(proto.Ack_ErrCode_ok, "")
		metrics.Handler.Request(l.WithResult(metrics.Success)).Inc()
		return infra.MetricsResultOk
	case errors.Is(err, ErrContentMismatch):
		logger.Error("[TrustStore:chainPushHandler] Certificate already exists with different hash",
			"err", err, "chain", dec, "peer", h.request.Peer)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToVerify)
		metrics.Handler.Request(l.WithResult(metrics.ErrVerify)).Inc()
		return infra.MetricsErrInvalid
	case errors.Is(err, ErrValidation), errors.Is(err, ErrVerification):
		logger.Error("[TrustStore:chainPushHandler] Unable to verify certificate chain",
			"err", err, "chain", dec, "peer", h.request.Peer)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToVerify)
		metrics.Handler.Request(l.WithResult(metrics.ErrVerify)).Inc()
		return infra.MetricsErrInvalid
	default:
		logger.Error("[TrustStore:chainPushHandler] Error inserting certificate chain",
			"err", err, "chain", dec, "peer", h.request.Peer)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRetryDBError)
		metrics.Handler.Request(l.WithResult(metrics.ErrInternal)).Inc()
		return infra.MetricsErrInternal
	}
}

type trcPushHandler struct {
	request  *infra.Request
	provider CryptoProvider
	inserter Inserter
	ia       addr.IA
}

func (h *trcPushHandler) Handle() *infra.HandlerResult {
	l := metrics.HandlerLabels{ReqType: metrics.TRCPush, Client: infra.PromSrcUnknown}
	if h.request == nil {
		log.Error("[TrustStore:trcPushHandler] Request is nil")
		return infra.MetricsErrInternal
	}
	l.Client = peerToLabel(h.request.Peer, h.ia)

	ctx := metrics.CtxWith(h.request.Context(), metrics.TRCPush)
	logger := log.FromCtx(ctx)
	// XXX(scrye): In case a TRC update will invalidate the local certificate
	// chain after the gracePeriod, CSes must use this gracePeriod to fetch a
	// new chain from the issuer. If a chain is not obtained within the
	// gracePeriod, manual intervention is required to install a valid chain.
	trcPush, ok := h.request.Message.(*cert_mgmt.TRC)
	if !ok {
		logger.Error("[TrustStore:trcPushHandler] Wrong message type, expected cert_mgmt.TRC",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		metrics.Handler.Request(l.WithResult(metrics.ErrInternal)).Inc()
		return infra.MetricsErrInternal
	}
	logger.Trace("[TrustStore:trcPushHandler] Received push", "trcPush", trcPush,
		"peer", h.request.Peer)
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Warn(
			"[TrustStore:trcPushHandler] Unable to service request, no ResponseWriter found")
		metrics.Handler.Request(l.WithResult(metrics.ErrInternal)).Inc()
		return infra.MetricsErrInternal
	}
	sendAck := messenger.SendAckHelper(ctx, rw)

	dec, err := decoded.DecodeTRC(trcPush.RawTRC)
	if err != nil {
		logger.Error("[TrustStore:trcPushHandler] Unable to parse TRC from push", "err", err)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		metrics.Handler.Request(l.WithResult(metrics.ErrParse)).Inc()
		return infra.MetricsErrInvalid
	}
	err = h.inserter.InsertTRC(ctx, dec, newTRCGetter(h.provider, h.request.Peer))
	switch {
	case err == nil:
		sendAck(proto.Ack_ErrCode_ok, "")
		metrics.Handler.Request(l.WithResult(metrics.Success)).Inc()
		return infra.MetricsResultOk
	case errors.Is(err, ErrContentMismatch):
		logger.Error("[TrustStore:trcPushHandler] TRC already exists with different hash",
			"err", err, "trc", dec, "peer", h.request.Peer)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToVerify)
		metrics.Handler.Request(l.WithResult(metrics.ErrVerify)).Inc()
		return infra.MetricsErrInvalid
	case errors.Is(err, ErrValidation), errors.Is(err, ErrVerification):
		logger.Error("[TrustStore:trcPushHandler] Unable to verify TRC",
			"err", err, "trc", dec, "peer", h.request.Peer)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToVerify)
		metrics.Handler.Request(l.WithResult(metrics.ErrVerify)).Inc()
		return infra.MetricsErrInvalid
	default:
		logger.Error("[TrustStore:trcPushHandler] Error inserting TRC",
			"err", err, "trc", dec, "peer", h.request.Peer)
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRetryDBError)
		metrics.Handler.Request(l.WithResult(metrics.ErrInternal)).Inc()
		return infra.MetricsErrInternal
	}
}

func newTRCGetter(provider CryptoProvider, peer net.Addr) func(context.Context,
	TRCID) (*trc.TRC, error) {

	return func(ctx context.Context, id TRCID) (*trc.TRC, error) {
		opts := infra.TRCOpts{
			TrustStoreOpts: infra.TrustStoreOpts{
				Server: peer,
			},
			AllowInactive: true,
		}
		return provider.GetTRC(ctx, id, opts)
	}
}

func peerToLabel(peer net.Addr, local addr.IA) string {
	var ia addr.IA
	switch v := peer.(type) {
	case *snet.SVCAddr:
		ia = v.IA
	case *snet.UDPAddr:
		ia = v.IA
	default:
		return infra.PromSrcUnknown
	}

	switch {
	case ia.Equal(local):
		return infra.PromSrcASLocal
	case ia.I == local.I:
		return infra.PromSrcISDLocal
	default:
		return infra.PromSrcISDRemote
	}
}
