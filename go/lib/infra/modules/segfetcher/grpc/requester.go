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

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/proto"
)

// Requester fetches segments from a remote using gRPC.
type Requester struct {
	// Dialer dials a new gRPC connection.
	Dialer grpc.Dialer
}

func (f *Requester) Segments(ctx context.Context, req segfetcher.Request,
	server net.Addr) (*path_mgmt.SegRecs, error) {

	conn, err := f.Dialer.Dial(ctx, server)
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
	segs := &path_mgmt.SegRecs{}
	if err := proto.ParseFromRaw(segs, rep.Raw); err != nil {
		return nil, serrors.WrapStr("parsing records", err)
	}
	if err := segs.ParseRaw(); err != nil {
		return nil, serrors.WrapStr("parsing individual records", err)
	}
	return segs, nil
}
