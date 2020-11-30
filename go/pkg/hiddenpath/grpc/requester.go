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

	"golang.org/x/sync/errgroup"

	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/serrors"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	hppb "github.com/scionproto/scion/go/pkg/proto/hidden_segment"
)

// Requester fetches segments from a remote using gRPC.
type Requester struct {
	// Dialer dials a new gRPC connection.
	Dialer libgrpc.Dialer
	// HPGroups is used to fetch hidden segments when the destination IA belongs
	// to the writers of a group configuration.
	HPGroups hiddenpath.Groups
	// RegularLookup is the regular segment lookup.
	RegularLookup segfetcher.RPC
}

func (f *Requester) Segments(ctx context.Context, req segfetcher.Request,
	server net.Addr) ([]*seg.Meta, error) {

	var (
		regularSegs []*seg.Meta
		hiddenSegs  []*seg.Meta
	)

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		segs, err := f.RegularLookup.Segments(ctx, req, server)
		if err != nil {
			return err
		}
		regularSegs = segs
		return nil
	})

	g.Go(func() error {
		segs, err := f.hiddenSegments(ctx, req, server)
		if err != nil {
			return err
		}
		hiddenSegs = segs
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return append(regularSegs, hiddenSegs...), nil
}

func (f *Requester) hiddenSegments(ctx context.Context, req segfetcher.Request,
	server net.Addr) ([]*seg.Meta, error) {

	conn, err := f.Dialer.Dial(ctx, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	groups := []uint64{}
	for _, g := range f.HPGroups {
		if _, ok := g.Writers[req.Dst]; ok {
			groups = append(groups, g.ID.ToUint64())
		}
	}

	if len(groups) == 0 {
		return nil, nil
	}

	client := hppb.NewHiddenSegmentLookupServiceClient(conn)
	rep, err := client.HiddenSegments(ctx,
		&hppb.HiddenSegmentsRequest{
			GroupIds: groups,
			DstIsdAs: uint64(req.Dst.IAInt()),
		},
		libgrpc.RetryProfile...,
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
