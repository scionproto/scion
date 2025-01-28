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
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/experimental/hiddenpath"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	hspb "github.com/scionproto/scion/pkg/proto/hidden_segment"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/segment/segfetcher"
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
	server net.Addr) (segfetcher.SegmentsReply, error) {

	var (
		regularReply segfetcher.SegmentsReply
		hiddenSegs   []*seg.Meta
	)

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		defer log.HandlePanic()
		r, err := f.RegularLookup.Segments(ctx, req, server)
		if err != nil {
			return err
		}
		regularReply = r
		return nil
	})

	g.Go(func() error {
		defer log.HandlePanic()
		segs, err := f.hiddenSegments(ctx, req, server)
		if err != nil {
			return err
		}
		hiddenSegs = segs
		return nil
	})

	if err := g.Wait(); err != nil {
		return segfetcher.SegmentsReply{}, err
	}

	// XXX(lukedirtwalker): this is a bit of a hack, the hidden segments could
	// theoretically have a different verification endpoint than the regular
	// segments, but since the API only allows to return one peer we assume they
	// come from the same CS, which is currently the case.
	return segfetcher.SegmentsReply{
		Segments: append(regularReply.Segments, hiddenSegs...),
		Peer:     regularReply.Peer,
	}, nil
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

	client := hspb.NewHiddenSegmentLookupServiceClient(conn)
	rep, err := client.HiddenSegments(ctx,
		&hspb.HiddenSegmentsRequest{
			GroupIds: groups,
			DstIsdAs: uint64(req.Dst),
		},
		libgrpc.RetryProfile...,
	)
	if err != nil {
		return nil, err
	}
	return unpackSegs(rep.Segments)
}

// AuthoritativeRequester requests hidden segments from an authoritative server.
type AuthoritativeRequester struct {
	// Dialer dials a new gRPC connection.
	Dialer libgrpc.Dialer
	// Signer is used to sign the requests.
	Signer Signer
}

// HiddenSegments requests from the authoritative server.
func (r AuthoritativeRequester) HiddenSegments(ctx context.Context,
	req hiddenpath.SegmentRequest, server net.Addr) ([]*seg.Meta, error) {

	conn, err := r.Dialer.Dial(ctx, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	groups := []uint64{}
	for _, id := range req.GroupIDs {
		groups = append(groups, id.ToUint64())
	}

	pbReq := &hspb.HiddenSegmentsRequest{
		GroupIds: groups,
		DstIsdAs: uint64(req.DstIA),
	}
	rawReq, err := proto.Marshal(pbReq)
	if err != nil {
		return nil, serrors.Wrap("marshaling request", err)
	}
	signedReq, err := r.Signer.Sign(ctx, rawReq)
	if err != nil {
		return nil, serrors.Wrap("signing request", err)
	}

	client := hspb.NewAuthoritativeHiddenSegmentLookupServiceClient(conn)
	rep, err := client.AuthoritativeHiddenSegments(ctx, &hspb.AuthoritativeHiddenSegmentsRequest{
		SignedRequest: signedReq,
	}, libgrpc.RetryProfile...)
	if err != nil {
		return nil, err
	}
	return unpackSegs(rep.Segments)
}

func unpackSegs(pbSegs map[int32]*hspb.Segments) ([]*seg.Meta, error) {
	var segs []*seg.Meta
	for segType, segments := range pbSegs {
		for i, pb := range segments.Segments {
			ps, err := seg.SegmentFromPB(pb)
			if err != nil {
				return nil, serrors.Wrap("parsing segments", err, "index", i)
			}
			segs = append(segs, &seg.Meta{
				Type:    seg.Type(segType),
				Segment: ps,
			})
		}
	}
	return segs, nil
}
