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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	hspb "github.com/scionproto/scion/go/pkg/proto/hidden_segment"
)

// RegistrationServer handles gRPC segment registration requests.
type RegistrationServer struct {
	Registry hiddenpath.Registry
}

// HiddenSegmentRegistration handles the gRPC hidden segment registration
// request.
func (s RegistrationServer) HiddenSegmentRegistration(ctx context.Context,
	req *hspb.HiddenSegmentRegistrationRequest) (*hspb.HiddenSegmentRegistrationResponse, error) {

	id := hiddenpath.GroupIDFromUint64(req.GroupId)
	rawPeer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "couldn't extract peer")
	}
	var segs []*seg.Meta
	for rawType, rawSegs := range req.Segments {
		for i, rawSeg := range rawSegs.Segments {
			s, err := seg.SegmentFromPB(rawSeg)
			if err != nil {
				return nil, status.Error(codes.InvalidArgument,
					fmt.Sprintf("invalid segment %d: %v", i, err))
			}
			segs = append(segs, &seg.Meta{
				Segment: s,
				Type:    seg.Type(rawType),
			})
		}
	}
	err := s.Registry.Register(ctx, hiddenpath.Registration{
		Segments: segs,
		GroupID:  id,
		Peer:     rawPeer.Addr,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &hspb.HiddenSegmentRegistrationResponse{}, nil
}
