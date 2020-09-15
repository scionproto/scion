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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	csmetrics "github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/tracing"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

var _ cppb.SegmentRegistrationServiceServer

// RegistrationServer handles segment registration requests.
type RegistrationServer struct {
	SegHandler seghandler.Handler

	// Requests aggregates all the incoming registration requests. If it is not
	// initialized, nothing is reported.
	Registrations metrics.Counter
}

func (s *RegistrationServer) SegmentsRegistration(ctx context.Context,
	req *cppb.SegmentsRegistrationRequest) (*cppb.SegmentsRegistrationResponse, error) {

	logger := log.FromCtx(ctx)
	span := opentracing.SpanFromContext(ctx)

	labels := requestLabels{
		Source: "unknown",
	}

	gPeer, ok := peer.FromContext(ctx)
	if !ok {
		err := serrors.New("peer must exist")
		s.failMetric(span, labels.WithResult(csmetrics.ErrInternal), err)
		return nil, err
	}
	peer, ok := gPeer.Addr.(*snet.UDPAddr)
	if !ok {
		err := serrors.New("peer must be *snet.UDPAddr", "actual", fmt.Sprintf("%T", gPeer))
		logger.Debug("Wrong peer type", "err", err)
		s.failMetric(span, labels.WithResult(csmetrics.ErrInternal), err)
		return nil, err
	}
	labels.Type = classifySegs(logger, req.Segments)

	var segs []*seg.Meta
	for segType, segments := range req.Segments {
		for _, pb := range segments.Segments {
			ps, err := seg.SegmentFromPB(pb)
			if err != nil {
				s.failMetric(span, labels.WithResult(csmetrics.ErrParse), err)
				return nil, status.Error(codes.InvalidArgument, "failed to parse segments")
			}
			segs = append(segs, &seg.Meta{
				Type:    seg.Type(segType),
				Segment: ps,
			})
		}
	}

	res := s.SegHandler.Handle(ctx,
		seghandler.Segments{
			Segs:      segs,
			SRevInfos: nil,
		},
		&snet.SVCAddr{
			IA:      peer.IA,
			Path:    peer.Path,
			NextHop: peer.NextHop,
			SVC:     addr.SvcCS,
		},
	)
	if err := res.Err(); err != nil {
		s.failMetric(span, labels.WithResult(csmetrics.ErrProcess), err)
		// TODO(roosd): Classify crypto/db error and return appropriate status code.
		return nil, err
	}
	s.successMetric(span, labels, res.Stats())
	return &cppb.SegmentsRegistrationResponse{}, nil
}

func (s *RegistrationServer) failMetric(span opentracing.Span, l requestLabels, err error) {
	if s.Registrations != nil {
		s.Registrations.With(l.Expand()...).Add(1)
	}
	if span != nil {
		tracing.ResultLabel(span, l.Result)
		tracing.Error(span, err)
	}
}

func (s *RegistrationServer) successMetric(span opentracing.Span, labels requestLabels,
	stats seghandler.Stats) {

	if s.Registrations != nil {
		s.Registrations.With(labels.WithResult(csmetrics.OkRegistrationNew).Expand()...).Add(
			float64(stats.SegsInserted()))
		s.Registrations.With(labels.WithResult(csmetrics.OkRegiststrationUpdated).Expand()...).Add(
			float64(stats.SegsUpdated()))
	}
	if span != nil {
		tracing.ResultLabel(span, csmetrics.OkSuccess)
		span.SetTag("segments_inserted", stats.SegsInserted())
		span.SetTag("segments_updated", stats.SegsUpdated())
	}
}

type requestLabels struct {
	Source string
	Type   string
	Result string
}

func (l requestLabels) Expand() []string {
	return []string{
		"src", l.Source,
		"type", l.Type,
		prom.LabelResult, l.Result,
	}
}

func (l requestLabels) WithResult(result string) requestLabels {
	l.Result = result
	return l
}

// classifySegs determines the type of segments that are registered. In the
// current implementation there should always be exactly 1 entry so 1 type can
// be returned. However the type allows multiple segments to be registered, so
// this function will concatenate the types if there are multiple segments of
// different types.
func classifySegs(logger log.Logger,
	segs map[int32]*cppb.SegmentsRegistrationRequest_Segments) string {

	if len(segs) > 1 {
		types := make([]seg.Type, 0, len(segs))
		for t := range segs {
			types = append(types, seg.Type(t))
		}
		logger.Info("SegReg contained multiple types, reporting unset in metrics", "types", types)
		return "multi"
	}
	for t := range segs {
		return seg.Type(t).String()
	}
	return "unset"
}
