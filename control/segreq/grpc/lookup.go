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

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/private/prom"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/segment/segfetcher"
	"github.com/scionproto/scion/private/tracing"
)

// Lookuper looks up path segments.
type Lookuper interface {
	LookupSegments(ctx context.Context, src, dst addr.IA) (segfetcher.Segments, error)
}

// LookupServer handles path segment lookups.
type LookupServer struct {
	Lookuper Lookuper
	RevCache revcache.RevCache

	// Requests aggregates all the incoming requests received by the handler.
	// If it is not initialized, nothing is reported.
	Requests func(segType string, dstISD addr.ISD, result string) metrics.Counter
	// SegmentsSent aggregates the number of segments that were transmitted in
	// response to a segment request.
	SegmentsSent func(segType string, dstISD addr.ISD) metrics.Counter
}

func (s LookupServer) Segments(ctx context.Context,
	req *cppb.SegmentsRequest) (*cppb.SegmentsResponse, error) {

	src, dst := addr.IA(req.SrcIsdAs), addr.IA(req.DstIsdAs)
	labels := requestLabels{
		Desc: descLabels{
			DstISD: dst.ISD(),
		},
	}
	logger := log.FromCtx(ctx)
	span := opentracing.SpanFromContext(ctx)
	setQueryTags(span, src, dst)
	logger.Debug("Received segment request", "src", src, "dst", dst)

	segs, err := s.Lookuper.LookupSegments(ctx, src, dst)
	if err != nil {
		logger.Debug("Failed to lookup requested segments", "err", err)
		s.updateMetric(span, labels.WithResult(segfetcher.ErrToMetricsLabel(err)), err)
		if len(segs) == 0 {
			// TODO(roosd): Differentiate errors and expose the applicable gRPC
			// status codes.
			return nil, err
		}
		// We have some segments and continue with a partial result.
	}

	labels.Desc.SegType = determineReplyType(segs)
	if span != nil {
		span.SetTag("seg_type", labels.Desc.SegType)
	}

	m := map[int32]*cppb.SegmentsResponse_Segments{}
	for _, meta := range segs {
		s, ok := m[int32(meta.Type)]
		if !ok {
			s = &cppb.SegmentsResponse_Segments{}
			m[int32(meta.Type)] = s
		}
		s.Segments = append(s.Segments, seg.PathSegmentToPB(meta.Segment))
	}

	logger.Debug("Replied with segments", "count", len(segs))
	s.updateMetric(span, labels.WithResult(prom.Success), nil)
	if s.SegmentsSent != nil {
		metrics.CounterAdd(s.SegmentsSent(labels.Desc.SegType, labels.Desc.DstISD), float64(len(segs)))
	}
	return &cppb.SegmentsResponse{
		Segments: m,
	}, nil
}

func (s LookupServer) updateMetric(span opentracing.Span, l requestLabels, err error) {
	if s.Requests != nil {
		metrics.CounterInc(s.Requests(l.Desc.SegType, l.Desc.DstISD, l.Result))
	}
	if span != nil {
		tracing.ResultLabel(span, l.Result)
		tracing.Error(span, err)
	}
}

func setQueryTags(span opentracing.Span, src, dst addr.IA) {
	if span != nil {
		span.SetTag("query.src", src)
		span.SetTag("query.dst", dst)
	}
}

type requestLabels struct {
	Desc   descLabels
	Result string
}

func (l requestLabels) WithResult(result string) requestLabels {
	l.Result = result
	return l
}

type descLabels struct {
	SegType string
	DstISD  addr.ISD
}

// determineReplyType determines which type of segments is in the reply. The
// method assumes that segs only contains one type of segments.
func determineReplyType(segs segfetcher.Segments) string {
	if len(segs) > 0 {
		return segs[0].Type.String()
	}
	return "none"
}
