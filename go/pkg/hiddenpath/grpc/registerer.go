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

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/cs/beaconing"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/serrors"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
	"github.com/scionproto/scion/go/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
	hppb "github.com/scionproto/scion/go/pkg/proto/hidden_segment"
	hspb "github.com/scionproto/scion/go/pkg/proto/hidden_segment"
)

// Signer signs requests.
type Signer interface {
	// Sign signs the msg and returns a signed message.
	Sign(ctx context.Context, msg []byte, associatedData ...[]byte) (*cryptopb.SignedMessage, error)
}

// Registerer can be used to register segments to remotes.
type Registerer struct {
	// Dialer dials a new gRPC connection.
	Dialer libgrpc.Dialer
	// RegularRegistration is the regular segment registration.
	RegularRegistration beaconing.RPC
	// Signer signs segment registration requests.
	Signer Signer
}

// RegisterSegment registers the segment at the remote. If the hidden path group
// ID is not defined it is registered via a normal segment registration message
func (s Registerer) RegisterSegment(ctx context.Context,
	reg hiddenpath.SegmentRegistration, remote net.Addr) error {

	if reg.Seg.Segment == nil {
		return serrors.New("no segments to register")
	}
	if reg.GroupID.ToUint64() == 0 { // do regular public registration
		return s.RegularRegistration.RegisterSegment(ctx, reg.Seg, remote)
	}

	conn, err := s.Dialer.Dial(ctx, remote)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := hspb.NewHiddenSegmentRegistrationServiceClient(conn)
	body := &hspb.HiddenSegmentRegistrationRequestBody{
		GroupId: reg.GroupID.ToUint64(),
		Segments: map[int32]*hppb.Segments{
			int32(reg.Seg.Type): {Segments: []*control_plane.PathSegment{
				seg.PathSegmentToPB(reg.Seg.Segment),
			}},
		},
	}
	rawBody, err := proto.Marshal(body)
	if err != nil {
		return err
	}
	signedMsg, err := s.Signer.Sign(ctx, rawBody)
	if err != nil {
		return err
	}
	req := &hspb.HiddenSegmentRegistrationRequest{SignedRequest: signedMsg}
	_, err = client.HiddenSegmentRegistration(ctx, req, libgrpc.RetryProfile...)
	return err
}
