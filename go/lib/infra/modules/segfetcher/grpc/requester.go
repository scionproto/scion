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
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

const (
	// DefaultRPCDialTimeout is the timeout used for dialing the gRPC ClientConn.
	// This is shorter than the typical context deadline for the request.
	// Having a separate, more aggressive timeout for dialing allows to abort
	// quickly. This allows the surrounding infrastructure to retry quickly -- in
	// the case where this request goes over SCION/QUIC, retries are used to
	// route around broken paths.
	// This timeout needs to be long enough to allow for service address
	// resolution and the QUIC handshake to complete (two roundtrips).
	DefaultRPCDialTimeout time.Duration = 1 * time.Second
)

// Requester fetches segments from a remote using gRPC.
type Requester struct {
	// Dialer dials a new gRPC connection.
	Dialer grpc.Dialer
}

func (f *Requester) Segments(ctx context.Context, req segfetcher.Request,
	server net.Addr) ([]*seg.Meta, error) {

	dialCtx, cancelF := context.WithTimeout(ctx, DefaultRPCDialTimeout)
	defer cancelF()
	conn, err := f.Dialer.Dial(dialCtx, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := cppb.NewSegmentLookupServiceClient(conn)
	rep, err := client.Segments(ctx,
		&cppb.SegmentsRequest{
			SrcIsdAs: uint64(req.Src.IAInt()),
			DstIsdAs: uint64(req.Dst.IAInt()),
		},
		grpc.RetryProfile...,
	)
	if err != nil {
		return nil, err
	}
	var segs []*seg.Meta
	for segType, segments := range rep.Segments {
		for i, pb := range segments.Segments {
			ps, err := seg.SegmentFromPB(pb)
			if err != nil {
				return nil, serrors.WrapStr("parsing segments", err, "index", i)
			}
			segs = append(segs, &seg.Meta{
				Type:    seg.Type(segType),
				Segment: ps,
			})
		}
	}
	return segs, nil
}
