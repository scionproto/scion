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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	hspb "github.com/scionproto/scion/go/pkg/proto/hidden_segment"
)

// SegmentServer serves segments from a lookuper.
type SegmentServer struct {
	Lookup hiddenpath.Lookuper
}

// HiddenSegments serves hidden segments requests using the provided lookup.
func (s *SegmentServer) HiddenSegments(ctx context.Context,
	pbReq *hspb.HiddenSegmentsRequest) (*hspb.HiddenSegmentsResponse, error) {

	logger := log.FromCtx(ctx)
	if pbReq == nil {
		logger.Debug("invalid request")
		return nil, status.Error(codes.Internal, "invalid request")
	}
	req := fromHSPB(pbReq)
	reply, err := s.Lookup.Segments(ctx, req)
	if err != nil {
		// TODO(lukedirtwalker): determine the proper error code here.
		logger.Debug("Failed to look up segments", "err", err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &hspb.HiddenSegmentsResponse{
		Segments: toHSPB(reply),
	}, nil
}

// AuthoritativeSegmentServer serves hidden segments from a lookuper and
// verifies that requests are correctly signed from the peer.
type AuthoritativeSegmentServer struct {
	Lookup   hiddenpath.Lookuper
	Verifier infra.Verifier
}

// AuthoritativeHiddenSegments serves the given hidden segments request.
func (s AuthoritativeSegmentServer) AuthoritativeHiddenSegments(ctx context.Context,
	pbReq *hspb.AuthoritativeHiddenSegmentsRequest,
) (*hspb.AuthoritativeHiddenSegmentsResponse, error) {

	logger := log.FromCtx(ctx)
	if pbReq == nil {
		logger.Debug("invalid request")
		return nil, status.Error(codes.Internal, "invalid request")
	}
	p, peerIA, err := getPeer(ctx)
	if err != nil {
		logger.Debug("Extracting peer", "err", err)
		return nil, status.Error(codes.Internal, "extracting peer")
	}
	msg, err := s.Verifier.WithIA(peerIA).WithServer(p).Verify(ctx, pbReq.SignedRequest)
	if err != nil {
		logger.Debug("Verifying request", "err", err)
		return nil, status.Error(codes.Unauthenticated, "verifying signature")
	}
	var r hspb.HiddenSegmentsRequest
	if err := proto.Unmarshal(msg.Body, &r); err != nil {
		logger.Debug("Parsing body", "err", err)
		return nil, status.Error(codes.InvalidArgument, "parsing body")
	}
	req := fromHSPB(&r)
	req.Peer = peerIA
	reply, err := s.Lookup.Segments(ctx, req)
	if err != nil {
		// TODO(lukedirtwalker): determine the proper error code here.
		logger.Debug("Failed to look up segments", "err", err)
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &hspb.AuthoritativeHiddenSegmentsResponse{
		Segments: toHSPB(reply),
	}, nil
}

func fromHSPB(pbReq *hspb.HiddenSegmentsRequest) hiddenpath.SegmentRequest {
	groups := make([]hiddenpath.GroupID, 0, len(pbReq.GroupIds))
	for _, id := range pbReq.GroupIds {
		groups = append(groups, hiddenpath.GroupIDFromUint64(id))
	}
	return hiddenpath.SegmentRequest{
		GroupIDs: groups,
		DstIA:    addr.IAInt(pbReq.DstIsdAs).IA(),
	}
}

func toHSPB(input []*seg.Meta) map[int32]*hspb.Segments {
	segments := make(map[int32]*hspb.Segments)
	for _, meta := range input {
		s, ok := segments[int32(meta.Type)]
		if !ok {
			s = &hspb.Segments{}
			segments[int32(meta.Type)] = s
		}
		s.Segments = append(s.Segments, seg.PathSegmentToPB(meta.Segment))
	}
	return segments
}
