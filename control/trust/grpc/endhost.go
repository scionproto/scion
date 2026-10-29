// Copyright 2026 ETH Zurich
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
	"time"

	"github.com/opentracing/opentracing-go"
	"google.golang.org/grpc/peer"

	trustmetrics "github.com/scionproto/scion/control/trust/metrics"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
	ehpb "github.com/scionproto/scion/pkg/proto/endhost"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/tracing"
	"github.com/scionproto/scion/private/trust"
)

type EndhostServer struct {
	// Provider provides the trust material.
	Provider trust.Provider
	// IA is the local ISD-AS.
	IA       addr.IA
	Requests metrics.Counter
}

func (s EndhostServer) Chains(ctx context.Context,
	req *ehpb.ListChainsRequest) (*ehpb.ListChainsResponse, error) {
	labels := requestLabels{
		ReqType: trustmetrics.ChainsReq,
		Client:  "unknown",
	}
	peer, ok := peer.FromContext(ctx)
	if ok {
		labels.Client = trustmetrics.PeerToLabel(peer.Addr, s.IA)
	}
	span := opentracing.SpanFromContext(ctx)
	logger := log.FromCtx(ctx)
	logger.Debug("Received chains request", "subjects", req.Subjects, "peer", peer.Addr)

	var validity cppki.Validity
	if !(req.AtLeastValidSince == 0 && req.AtLeastValidUntil == 0) {
		validity.NotAfter = time.Unix(int64(req.AtLeastValidUntil), 0)
		validity.NotBefore = time.Unix(int64(req.AtLeastValidSince), 0)
	}
	rep := &ehpb.ListChainsResponse{
		Chains: make([]*ehpb.Chain, 0, len(req.Subjects)),
	}
	for _, subject := range req.Subjects {
		query := trust.ChainQuery{
			IA:           addr.IA(subject.IsdAs),
			SubjectKeyID: subject.SubjectKeyId,
			Validity:     validity,
		}
		chains, err := s.Provider.GetChains(ctx, query, trust.AllowInactive(),
			trust.Client(peer.Addr))
		if err != nil {
			logger.Info("Unable to retrieve chains", "query", query, "err", err)
			s.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), err)
			return nil, err
		}
		for _, chain := range chains {
			rep.Chains = append(rep.Chains, &ehpb.Chain{
				Subject: subject,
				AsCert:  chain[0].Raw,
				CaCert:  chain[1].Raw,
			})
		}
	}
	logger.Debug("Replied with chains", "count", len(rep.Chains))
	s.updateMetric(span, labels.WithResult(trustmetrics.Success), nil)
	return rep, nil
}

func (s *EndhostServer) updateMetric(span opentracing.Span, l requestLabels, err error) {
	if s.Requests != nil {
		s.Requests.With(l.Expand()...).Add(1)
	}
	if span != nil {
		tracing.ResultLabel(span, l.Result)
		tracing.Error(span, err)
	}
}

func (s *EndhostServer) TRC(ctx context.Context, req *ehpb.TRCRequest) (*ehpb.TRCResponse, error) {
	labels := requestLabels{
		ReqType: trustmetrics.TRCReq,
		Client:  "unknown",
	}
	peer, ok := peer.FromContext(ctx)
	if ok {
		labels.Client = trustmetrics.PeerToLabel(peer.Addr, s.IA)
	}
	trcID := cppki.TRCID{
		ISD:    addr.ISD(req.Isd),
		Base:   scrypto.Version(req.Base),
		Serial: scrypto.Version(req.Serial),
	}
	span := opentracing.SpanFromContext(ctx)
	setTRCTags(span, trcID)
	logger := log.FromCtx(ctx)
	logger.Debug("Received TRC request", "id", trcID, "peer", peer.Addr)

	if req.Isd > uint32(addr.MaxISD) {
		err := serrors.New("requested ISD not in range",
			"max", addr.MaxISD, "isd", req.Isd)
		logger.Debug("Invalid TRC request", "peer", peer.Addr, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), err)
		return nil, err
	}

	if !(trcID.Base.IsLatest() && trcID.Serial.IsLatest()) {
		if err := trcID.Validate(); err != nil {
			logger.Debug("Invalid TRC request", "peer", peer.Addr, "err", err)
			s.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), err)
			return nil, err
		}
	} else if trcID.ISD == 0 {
		logger.Debug("Invalid TRC request", "peer", peer.Addr, "err", cppki.ErrWildcardISD)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrParse), cppki.ErrWildcardISD)
		return nil, cppki.ErrWildcardISD
	}
	trc, err := s.Provider.GetSignedTRC(ctx, trcID, trust.AllowInactive(), trust.Client(peer.Addr))
	if err != nil {
		logger.Info("Unable to retrieve TRC", "id", trcID, "err", err)
		s.updateMetric(span, labels.WithResult(trustmetrics.ErrInternal), err)
		return nil, err
	}
	return &ehpb.TRCResponse{
		Trc: trc.Raw,
	}, nil
}
