// Copyright 2023 Anapaya Systems
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

package connect

import (
	"context"
	"net"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/bufgen/proto/control_plane/v1/control_planeconnect"

	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/control_plane"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/private/segment/segfetcher"
	segfetchergrpc "github.com/scionproto/scion/private/segment/segfetcher/grpc"
)

// Requester fetches segments from a remote using gRPC.
type Requester struct {
	Dialer func(net.Addr, ...squic.EarlyDialerOption) squic.EarlyDialer
}

func (f *Requester) Segments(ctx context.Context, req segfetcher.Request,
	server net.Addr) (segfetcher.SegmentsReply, error) {

	peer := make(chan net.Addr, 1)
	dialer := f.Dialer(server, squic.WithPeerChannel(peer), squic.WithDialTimeout(segfetchergrpc.DefaultRPCDialTimeout))
	client := control_planeconnect.NewSegmentLookupServiceClient(
		libconnect.HTTPClient{
			RoundTripper: &http3.RoundTripper{
				Dial: dialer.DialEarly,
			},
		},
		libconnect.BaseUrl(server),
	)
	rep, err := client.Segments(ctx, connect.NewRequest(&control_plane.SegmentsRequest{
		SrcIsdAs: uint64(req.Src),
		DstIsdAs: uint64(req.Dst),
	}))
	if err != nil {
		return segfetcher.SegmentsReply{}, err
	}

	var resolvedPeer net.Addr
	select {
	case p := <-peer:
		resolvedPeer = p
	default:
		return segfetcher.SegmentsReply{}, serrors.New("no peer resolved", "server", server)
	}

	var segs []*seg.Meta
	for segType, segments := range rep.Msg.Segments {
		for i, pb := range segments.Segments {
			ps, err := seg.SegmentFromPB(pb)
			if err != nil {
				return segfetcher.SegmentsReply{},
					serrors.WrapStr("parsing segments", err, "index", i)
			}
			segs = append(segs, &seg.Meta{
				Type:    seg.Type(segType),
				Segment: ps,
			})
		}
	}
	return segfetcher.SegmentsReply{Segments: segs, Peer: resolvedPeer}, nil
}
