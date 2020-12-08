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
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	hspb "github.com/scionproto/scion/go/pkg/proto/hidden_segment"
)

// RegistrationServer handles gRPC segment registration requests.
type RegistrationServer struct {
	Registry hiddenpath.Registry
	Verifier infra.Verifier
}

// HiddenSegmentRegistration handles the gRPC hidden segment registration
// request.
func (s RegistrationServer) HiddenSegmentRegistration(ctx context.Context,
	req *hspb.HiddenSegmentRegistrationRequest) (*hspb.HiddenSegmentRegistrationResponse, error) {

	logger := log.FromCtx(ctx)

	p, peerIA, err := getPeer(ctx)
	if err != nil {
		logger.Debug("Failed to extract peer", "err", err)
		return nil, err
	}
	msg, err := s.Verifier.WithIA(peerIA).WithServer(p).Verify(ctx, req.SignedRequest)
	if err != nil {
		logger.Debug("Failed to verify signature", "err", err)
		return nil, status.Error(codes.Unauthenticated, "verifying signature")
	}
	var reqBody hspb.HiddenSegmentRegistrationRequestBody
	if err := proto.Unmarshal(msg.Body, &reqBody); err != nil {
		logger.Debug("Failed to parse body", "err", err)
		return nil, status.Error(codes.InvalidArgument, "parsing body")
	}
	id := hiddenpath.GroupIDFromUint64(reqBody.GroupId)
	var segs []*seg.Meta
	for rawType, rawSegs := range reqBody.Segments {
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
	err = s.Registry.Register(ctx, hiddenpath.Registration{
		Segments: segs,
		GroupID:  id,
		Peer:     p,
	})
	if err != nil {
		logger.Debug("Error during registration", "err", err)
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &hspb.HiddenSegmentRegistrationResponse{}, nil
}

func getPeer(ctx context.Context) (*snet.SVCAddr, addr.IA, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, addr.IA{}, serrors.New("not present", "ctx", ctx)
	}
	a, ok := p.Addr.(*snet.UDPAddr)
	if !ok {
		return nil, addr.IA{}, serrors.New("invalid type, expected snet.UDPAddr",
			"type", fmt.Sprintf("%T", p.Addr))
	}
	// XXX(lukedirtwalker): because the remote might send from the client QUIC
	// stack we can't simply use the peer address. So for now we just use the
	// SVC_CS address in the peer.
	return &snet.SVCAddr{
		IA:      a.IA,
		Path:    a.Path,
		NextHop: a.NextHop,
		SVC:     addr.SvcCS,
	}, a.IA, nil
}
