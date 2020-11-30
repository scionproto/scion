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
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	hspb "github.com/scionproto/scion/go/pkg/proto/hidden_segment"
)

// SegmentServer serves segments from a lookuper.
type SegmentServer struct {
	Lookup        hiddenpath.Lookuper
	Authoritative bool
}

// HiddenSegments serves hidden segments requests using the provided lookup.
func (s *SegmentServer) HiddenSegments(ctx context.Context,
	pbReq *hspb.HiddenSegmentsRequest) (*hspb.HiddenSegmentsResponse, error) {

	if pbReq == nil {
		return nil, status.Error(codes.Internal, "invalid request")
	}

	// TODO(karampok): tracing
	// TODO(karampok): metrics

	groups := make([]hiddenpath.GroupID, 0, len(pbReq.GroupIds))
	for _, id := range pbReq.GroupIds {
		groups = append(groups, hiddenpath.GroupIDFromUint64(id))
	}
	req := hiddenpath.SegmentRequest{
		GroupIDs: groups,
		DstIA:    addr.IAInt(pbReq.DstIsdAs).IA(),
	}

	if s.Authoritative {
		rawPeer, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Internal, "couldn't extract peer")
		}
		peerAddr, ok := rawPeer.Addr.(*snet.UDPAddr)
		if !ok {
			return nil, status.Error(codes.Internal, "peer is not snet.UDPAddr")
		}
		req.Peer = peerAddr.IA
	}

	reply, err := s.Lookup.Segments(ctx, req)
	if err != nil {
		// TODO(lukedirtwalker): determine the proper error code here.
		return nil, status.Error(codes.Internal, err.Error())
	}

	return toHSPB(reply), nil
}

func toHSPB(input []*seg.Meta) *hspb.HiddenSegmentsResponse {
	segments := make(map[int32]*hspb.Segments)
	for _, meta := range input {
		s, ok := segments[int32(meta.Type)]
		if !ok {
			s = &hspb.Segments{}
			segments[int32(meta.Type)] = s
		}
		s.Segments = append(s.Segments, seg.PathSegmentToPB(meta.Segment))
	}
	return &hspb.HiddenSegmentsResponse{
		Segments: segments,
	}
}
