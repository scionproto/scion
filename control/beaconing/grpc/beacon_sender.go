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

	"google.golang.org/grpc"

	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/control/onehop"
	"github.com/scionproto/scion/pkg/addr"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	seg "github.com/scionproto/scion/pkg/segment"
)

// BeaconSenderFactory can be used to create beacon senders.
type BeaconSenderFactory struct {
	// Dialer is used to dial the gRPC connection to the remote.
	Dialer libgrpc.Dialer
}

// NewSender returns a beacon sender that can be used to send beacons to a remote CS.
func (f *BeaconSenderFactory) NewSender(
	ctx context.Context,
	dstIA addr.IA,
	egIfID uint16,
	nextHop *net.UDPAddr,
) (beaconing.Sender, error) {
	addr := &onehop.Addr{
		IA:      dstIA,
		Egress:  egIfID,
		SVC:     addr.SvcCS,
		NextHop: nextHop,
	}
	conn, err := f.Dialer.Dial(ctx, addr)
	if err != nil {
		return nil, serrors.Wrap("dialing gRPC conn", err)
	}
	return &BeaconSender{
		Conn: conn,
	}, nil
}

// BeaconSender propagates beacons.
type BeaconSender struct {
	Conn *grpc.ClientConn
}

// Send sends a beacon to the remote.
func (s BeaconSender) Send(ctx context.Context, b *seg.PathSegment) error {
	client := cppb.NewSegmentCreationServiceClient(s.Conn)
	_, err := client.Beacon(ctx,
		&cppb.BeaconRequest{
			Segment: seg.PathSegmentToPB(b),
		},
		libgrpc.RetryProfile...,
	)
	return err
}

// Close closes the BeaconSender and releases all underlying resources.
func (s BeaconSender) Close() error {
	return s.Conn.Close()
}
