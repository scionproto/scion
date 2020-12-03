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

	"github.com/scionproto/scion/go/cs/beaconing"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	"github.com/scionproto/scion/go/pkg/proto/control_plane"
	hppb "github.com/scionproto/scion/go/pkg/proto/hidden_segment"
	hspb "github.com/scionproto/scion/go/pkg/proto/hidden_segment"
)

// Register can be used to register segments to remotes.
type Register struct {
	// Dialer dials a new gRPC connection.
	Dialer libgrpc.Dialer
	// RegularRegistration is the regular segment registration.
	RegularRegistration beaconing.RPC
}

// RegisterSegment registers the segment at the remote. If the hidden path group
// ID is not defined it is registered via a normal segment registration message
func (s Register) RegisterSegment(ctx context.Context,
	reg hiddenpath.SegmentRegistration, remote net.Addr) error {

	if reg.GroupID.ToUint64() == 0 { // do regular public registration
		return s.RegularRegistration.RegisterSegment(ctx, reg.Seg, remote)
	}

	conn, err := s.Dialer.Dial(ctx, remote)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := hspb.NewHiddenSegmentRegistrationServiceClient(conn)
	in := &hspb.HiddenSegmentRegistrationRequest{
		GroupId: reg.GroupID.ToUint64(),
		Segments: map[int32]*hppb.Segments{
			int32(reg.Seg.Type): {Segments: []*control_plane.PathSegment{
				seg.PathSegmentToPB(reg.Seg.Segment),
			}},
		},
	}
	_, err = client.HiddenSegmentRegistration(ctx, in, libgrpc.RetryProfile...)
	return err
}
