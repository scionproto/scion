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
	"sort"

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/control/segreq"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	ehpb "github.com/scionproto/scion/pkg/proto/endhost"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/segment/segfetcher"
	"github.com/scionproto/scion/private/tracing"
	"github.com/scionproto/scion/private/trust"
)

// LookupServer handles path segment lookups.
type EndhostServer struct {
	Lookuper     Lookuper
	Requests     metrics.Counter
	SegmentsSent metrics.Counter
	LocalIA      addr.IA
	IsCore       bool
	Inspector    trust.Inspector
	PathDB       pathdb.DB
	PathStore    *segreq.Store
	Paginator    *segreq.Paginator
}

func (s EndhostServer) ListSegments(ctx context.Context,
	req *ehpb.ListSegmentsRequest) (*ehpb.ListSegmentsResponse, error) {

	src, dst := addr.IA(req.SrcIsdAs), addr.IA(req.DstIsdAs)
	logger := log.FromCtx(ctx)
	span := opentracing.SpanFromContext(ctx)
	setQueryTags(span, src, dst)
	logger.Debug("Received ListSegments request", "src", src, "dst", dst)
	res := &ehpb.ListSegmentsResponse{}
	if src == dst {
		// intra AS path, no segments are returned
		s.updateMetric(span, prom.Success, nil)
		return res, nil
	}

	pageSize := req.PageSize
	if req.PageSize == 0 {
		pageSize = 64
	}
	allPaths, err := s.getPaths(ctx, src, dst)
	if err != nil {
		logger.Debug("Failed to lookup path segments", "err", err)
		s.updateMetric(span, segfetcher.ErrToMetricsLabel(err), err)
		return nil, err
	}

	resUp, resCore, resDown, nextPage := s.Paginator.GetPage(allPaths, int(pageSize), req.PageToken)
	res.NextPageToken = nextPage
	for _, segment := range resUp {
		res.UpSegments = append(res.UpSegments, seg.PathSegmentToPB(segment))
	}
	for _, segment := range resCore {
		res.CoreSegments = append(res.CoreSegments, seg.PathSegmentToPB(segment))
	}
	for _, segment := range resDown {
		res.DownSegments = append(res.DownSegments, seg.PathSegmentToPB(segment))
	}

	logger.Debug("Replied with segments", "up", len(res.UpSegments), "core", len(res.CoreSegments),
		"down", len(res.DownSegments))
	s.updateMetric(span, prom.Success, nil)
	s.incSegmentsSent(len(resUp) + len(resCore) + len(resDown))
	return res, nil
}

func (s EndhostServer) updateMetric(span opentracing.Span, result string, err error) {
	if s.Requests != nil {
		s.Requests.Add(1)
	}
	if span != nil {
		tracing.ResultLabel(span, result)
		tracing.Error(span, err)
	}
}
func (s EndhostServer) incSegmentsSent(segments int) {
	if s.SegmentsSent != nil {
		s.SegmentsSent.Add(float64(segments))
	}
}

// getPaths asks the PathStore whether paths from src IA to dst IA are cached, if yes
// it returns those, otherwise it performs the expensive operation of looking up
// all path segments relevant for connection between the src IA and dst IA
// (they might be cached in the path DB) and check whether they can be stitched together.
// In that case, the newely combined paths will be cached in the store.
func (s EndhostServer) getPaths(ctx context.Context, src, dst addr.IA) (
	[]segreq.CombinedPath, error) {
	if paths, found := s.PathStore.Get(src, dst); found {
		return paths, nil
	}
	splitter := segreq.NewSplitter(s.LocalIA, s.IsCore, s.Inspector, s.PathDB)
	reqs, err := splitter.Split(ctx, dst)
	if err != nil {
		return nil, err
	}

	upSegments := make(seg.Segments, 0, 1)
	coreSegments := make(seg.Segments, 0, 1)
	downSegments := make(seg.Segments, 0, 1)
	for i := 0; i < len(reqs); i++ {
		segs, err := s.Lookuper.LookupSegments(ctx, reqs[i].Src, reqs[i].Dst)
		if err != nil {
			return nil, err
		}
		for _, meta := range segs {
			switch meta.Type {
			case seg.TypeCore:
				coreSegments = append(coreSegments, meta.Segment)
			case seg.TypeDown:
				downSegments = append(downSegments, meta.Segment)
			case seg.TypeUp:
				upSegments = append(upSegments, meta.Segment)
			}
		}
	}
	allPaths := make([]segreq.CombinedPath, 0, 1)
	// check for single segment paths:
	isSingleSegment := false
	if len(upSegments) == 0 && len(coreSegments) == 0 {
		isSingleSegment = true
		for _, downSegment := range downSegments {
			allPaths = append(allPaths, segreq.CombinedPath{DownSegment: downSegment})
		}
	} else if len(upSegments) == 0 && len(downSegments) == 0 {
		isSingleSegment = true
		for _, coreSegment := range coreSegments {
			allPaths = append(allPaths, segreq.CombinedPath{CoreSegment: coreSegment})
		}
	} else if len(coreSegments) == 0 && len(downSegments) == 0 {
		isSingleSegment = true
		for _, upSegment := range upSegments {
			allPaths = append(allPaths, segreq.CombinedPath{UpSegment: upSegment})
		}
	}
	if !isSingleSegment {
		if len(upSegments) != 0 {
			// we have up + core + down, up + core, or up + down paths
			for _, upSegment := range upSegments {
				for _, coreSegment := range coreSegments {
					if upSegment.FirstIA() == coreSegment.FirstIA() ||
						upSegment.FirstIA() == coreSegment.LastIA() {

						if len(downSegments) != 0 {
							// we have up segment, core segment and down segment
							for _, downSegment := range downSegments {
								if coreSegment.FirstIA() == downSegment.FirstIA() ||
									coreSegment.LastIA() == downSegment.FirstIA() {
									allPaths = append(allPaths, segreq.CombinedPath{
										UpSegment:   upSegment,
										CoreSegment: coreSegment,
										DownSegment: downSegment,
									})
								}
							}
						} else {
							// we have up segment and core segment, but no down segment
							allPaths = append(allPaths, segreq.CombinedPath{
								UpSegment:   upSegment,
								CoreSegment: coreSegment,
							})
						}
					}
				}
				for _, downSegment := range downSegments {
					if upSegment.FirstIA() == downSegment.FirstIA() {
						// we have up segment and down segment, without a core segment
						allPaths = append(allPaths, segreq.CombinedPath{
							UpSegment:   upSegment,
							DownSegment: downSegment,
						})
					}
				}
			}
		} else {
			// we have only core + down paths
			for _, coreSegment := range coreSegments {
				for _, downSegment := range downSegments {
					if coreSegment.FirstIA() == downSegment.FirstIA() ||
						coreSegment.LastIA() == downSegment.FirstIA() {
						allPaths = append(allPaths, segreq.CombinedPath{
							CoreSegment: coreSegment,
							DownSegment: downSegment,
						})
					}
				}
			}
		}
	}
	sort.Slice(allPaths, func(i, j int) bool {
		return allPaths[i].Length() < allPaths[j].Length()
	})
	s.PathStore.Set(src, dst, allPaths)
	return allPaths, nil
}
