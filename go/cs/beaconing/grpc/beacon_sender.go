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
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	"github.com/scionproto/scion/go/proto"
)

// BeaconSender propagates beacons.
type BeaconSender struct {
	// Dialer dials a new gRPC connection.
	Dialer grpc.Dialer
}

// SendBeacon sends a beacon to the remote.
func (r BeaconSender) SendBeacon(ctx context.Context, b *seg.PathSegment, remote net.Addr) error {
	raw, err := proto.PackRoot(b)
	if err != nil {
		return serrors.WrapStr("packing beacon", err)
	}
	conn, err := r.Dialer.Dial(ctx, remote)
	if err != nil {
		return err
	}
	defer conn.Close()
	client := cppb.NewSegmentCreationServiceClient(conn)
	_, err = client.Beacon(ctx,
		&cppb.BeaconRequest{
			Raw: raw,
		},
		grpc.RetryProfile...,
	)
	return err
}
