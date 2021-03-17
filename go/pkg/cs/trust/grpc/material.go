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

package grpc

import (
	"context"
	"fmt"

	"github.com/opentracing/opentracing-go"
	"google.golang.org/grpc/peer"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/lib/util"
	trustmetrics "github.com/scionproto/scion/go/pkg/cs/trust/metrics"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/pkg/trust"
)

// MaterialServer servers trust material for gRPC requests.
type MaterialServer struct {
	// Provider provides the trust material.
	Provider trust.Provider
	// IA is the local ISD-AS.
	IA addr.IA

	// Requests aggregates all the incoming requests received by the handler. If
	// it is not initialized, nothing is reported.
	Requests metrics.Counter
}

func (s MaterialServer) Chains(ctx context.Context,
	req *cppb.ChainsRequest) (*cppb.ChainsResponse, error) {

	labels := requestLabels{
		ReqType: trustmetrics.ChainReq,
		Client:  infra.PromSrcUnknown,
	}
	peer, ok := peer.FromContext(ctx)
	if ok {
		labels.Client = trustmetrics.PeerToLabel(peer.Addr, s.IA)
	}
	span := opentracing.SpanFromContext(ctx)
	logger := log.FromCtx(ctx)

	query, err := requestToChainQuery(req)
	if err != nil {
		logger.Debug("Invalid chain request", "peer", peer.Addr, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), err)
		return nil, err
	}
	setChainsTags(span, query)
	logger.Debug("Received chain request", "query", query, "peer", peer.Addr)

	chains, err := s.Provider.GetChains(ctx, query, trust.AllowInactive(), trust.Client(peer.Addr))
	if err != nil {
		logger.Info("Unable to retrieve chains", "query", query, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrInternal), err)
		return nil, err
	}
	logger.Debug("Replied with chains", "count", len(chains))
	s.updateMetric(span, labels.WithResult(trustmetrics.Success), nil)
	return chainsToResponse(chains), nil
}

func (s MaterialServer) TRC(ctx context.Context, req *cppb.TRCRequest) (*cppb.TRCResponse, error) {
	labels := requestLabels{
		ReqType: trustmetrics.TRCReq,
		Client:  infra.PromSrcUnknown,
	}
	peer, ok := peer.FromContext(ctx)
	if ok {
		labels.Client = trustmetrics.PeerToLabel(peer.Addr, s.IA)
	}
	span := opentracing.SpanFromContext(ctx)
	logger := log.FromCtx(ctx)

	id, err := requestToTRCQuery(req)
	if err != nil {
		logger.Debug("Invalid TRC request", "peer", peer.Addr, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), err)
		return nil, err
	}
	setTRCTags(span, id)
	logger.Debug("Received TRC request", "id", id, "peer", peer.Addr)

	trc, err := s.Provider.GetSignedTRC(ctx, id, trust.AllowInactive(), trust.Client(peer.Addr))
	if err != nil {
		logger.Info("Unable to retrieve TRC", "id", id, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrInternal), err)
		return nil, err
	}
	logger.Debug("Replied with TRC", "id", id)
	s.updateMetric(span, labels.WithResult(trustmetrics.Success), nil)
	return trcToResponse(trc), nil
}

func (s MaterialServer) updateMetric(span opentracing.Span, l requestLabels, err error) {
	if s.Requests != nil {
		s.Requests.With(l.Expand()...).Add(1)
	}
	if span != nil {
		tracing.ResultLabel(span, l.Result)
		tracing.Error(span, err)
	}
}

func setChainsTags(span opentracing.Span, query trust.ChainQuery) {
	if span != nil {
		span.SetTag("query.isd_as", query.IA)
		span.SetTag("query.subject_key_id", fmt.Sprintf("%x", query.SubjectKeyID))
		span.SetTag("query.date", util.TimeToCompact(query.Date))
	}
}

func setTRCTags(span opentracing.Span, id cppki.TRCID) {
	if span != nil {
		span.SetTag("trc_id.isd", id.ISD)
		span.SetTag("trc_id.base", id.Base)
		span.SetTag("trc_id.serial", id.Serial)
	}
}

type requestLabels struct {
	Client  string
	ReqType string
	Result  string
}

func (l requestLabels) Expand() []string {
	return []string{
		"client", l.Client,
		"req_type", l.ReqType,
		prom.LabelResult, l.Result,
	}
}

func (l requestLabels) WithResult(result string) requestLabels {
	l.Result = result
	return l
}
