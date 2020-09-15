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

	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

// Registrar registers segments.
type Registrar struct {
	// Dialer dials a new gRPC connection.
	Dialer grpc.Dialer
}

// RegisterSegment registers a segment with the remote.
func (r Registrar) RegisterSegment(ctx context.Context, meta seg.Meta, remote net.Addr) error {
	conn, err := r.Dialer.Dial(ctx, remote)
	if err != nil {
		return err
	}
	defer conn.Close()
	client := cppb.NewSegmentRegistrationServiceClient(conn)
	_, err = client.SegmentsRegistration(ctx,
		&cppb.SegmentsRegistrationRequest{
			Segments: map[int32]*cppb.SegmentsRegistrationRequest_Segments{
				int32(meta.Type): {
					Segments: []*cppb.PathSegment{
						seg.PathSegmentToPB(meta.Segment),
					},
				},
			},
		},
		grpc.RetryProfile...,
	)
	return err
}
