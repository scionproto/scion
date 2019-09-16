// Copyright 2018 Anapaya Systems
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

package handlers

import (
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/path_srv/internal/metrics"
	"github.com/scionproto/scion/go/proto"
)

const (
	regLabelType   = "type"
	regLabelSrc    = "src_ia"
	regLabelResult = "result"
)

const (
	regResultNew       = "new"
	regResultUpdated   = "updated"
	regResultErrCrypto = "err_crypto"
	regResultErrDB     = "err_db"
	regResultErrParse  = "err_parse"
	regResultErrInt    = "err_internal"
)

var (
	regResults = []string{regResultNew, regResultUpdated, regResultErrCrypto,
		regResultErrDB, regResultErrInt}
	regsTotal *prometheus.CounterVec
)

type segRegHandler struct {
	*baseHandler
	localIA addr.IA
	handler seghandler.Handler
}

func NewSegRegHandler(args HandlerArgs) infra.Handler {
	regsTotal = prom.NewCounterVec(metrics.Namespace, "", "registrations_total",
		fmt.Sprintf("Number of path registrations. \"result\" can be one of: [%s]",
			strings.Join(regResults, ",")),
		[]string{regLabelType, regLabelSrc, regLabelResult})
	f := func(r *infra.Request) *infra.HandlerResult {
		handler := &segRegHandler{
			baseHandler: newBaseHandler(r, args),
			localIA:     args.IA,
			handler: seghandler.Handler{
				Verifier: &seghandler.DefaultVerifier{
					Verifier: args.VerifierFactory.NewVerifier(),
				},
				Storage: &seghandler.DefaultStorage{
					PathDB:   args.PathDB,
					RevCache: args.RevCache,
				},
			},
		}
		return handler.Handle()
	}
	return infra.HandlerFunc(f)
}

func (h *segRegHandler) Handle() *infra.HandlerResult {
	ctx := h.request.Context()
	logger := log.FromCtx(ctx)
	labels := prometheus.Labels{
		regLabelType:   "?",
		regLabelSrc:    "?",
		regLabelResult: regResultErrInt,
	}
	segReg, ok := h.request.Message.(*path_mgmt.SegReg)
	if !ok {
		logger.Error("[segRegHandler] wrong message type, expected path_mgmt.SegReg",
			"msg", h.request.Message, "type", common.TypeOf(h.request.Message))
		regsTotal.With(labels).Inc()
		return infra.MetricsErrInternal
	}
	snetPeer := h.request.Peer.(*snet.Addr)
	labels[regLabelType] = classifySegs(segReg)
	labels[regLabelSrc] = snetPeer.IA.String()
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Error("[segRegHandler] Unable to service request, no ReplyWriter found")
		regsTotal.With(labels).Inc()
		return infra.MetricsErrInternal
	}
	labels[regLabelResult] = regResultErrParse
	sendAck := messenger.SendAckHelper(ctx, rw)
	if err := segReg.ParseRaw(); err != nil {
		logger.Error("[segRegHandler] Failed to parse message", "err", err)
		regsTotal.With(labels).Inc()
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return infra.MetricsErrInvalid
	}
	logSegRecs(logger, "[segRegHandler]", h.request.Peer, segReg.SegRecs)

	peerPath, err := snetPeer.GetPath()
	if err != nil {
		logger.Error("[segRegHandler] Failed to initialize path", "err", err)
		regsTotal.With(labels).Inc()
		sendAck(proto.Ack_ErrCode_reject, messenger.AckRejectFailedToParse)
		return infra.MetricsErrInvalid
	}
	svcToQuery := &snet.Addr{
		IA:      snetPeer.IA,
		Path:    peerPath.Path(),
		NextHop: peerPath.OverlayNextHop(),
		Host:    addr.NewSVCUDPAppAddr(addr.SvcBS),
	}
	segs := seghandler.Segments{
		Segs:      segReg.Recs,
		SRevInfos: segReg.SRevInfos,
	}
	res := h.handler.Handle(ctx, segs, svcToQuery, nil)
	// wait until processing is done.
	<-res.FullReplyProcessed()
	if err := res.Err(); err != nil {
		// TODO(lukedirtwalker): classify crypto/db error
		labels[regLabelResult] = regResultErrDB
		regsTotal.With(labels).Inc()
		sendAck(proto.Ack_ErrCode_reject, err.Error())
		return infra.MetricsErrInvalid
	}
	h.incMetrics(labels, res.Stats())
	sendAck(proto.Ack_ErrCode_ok, "")
	return infra.MetricsResultOk
}

func (h *segRegHandler) incMetrics(labels prometheus.Labels, stats seghandler.Stats) {
	labels[regLabelResult] = regResultNew
	regsTotal.With(labels).Add(float64(len(stats.SegDB.InsertedSegs)))
	labels[regLabelResult] = regResultUpdated
	regsTotal.With(labels).Add(float64(len(stats.SegDB.UpdatedSegs)))
}

// classifySegs determines the type of segments that are registered. In the
// current implementation there should always be exactly 1 entry so 1 type can
// be returned. However the type allows multiple segments to be registered, so
// this function will concatenate the types if there are multiple segments of
// different types.
func classifySegs(segReg *path_mgmt.SegReg) string {
	segTypes := make(map[string]struct{}, 1)
	for _, segMeta := range segReg.Recs {
		segTypes[segMeta.Type.String()] = struct{}{}
	}
	var result strings.Builder
	for segType := range segTypes {
		result.WriteString(segType)
	}
	return result.String()
}
