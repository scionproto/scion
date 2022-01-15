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

	"google.golang.org/grpc"

	"github.com/scionproto/scion/go/cs/beaconing"
	"github.com/scionproto/scion/go/cs/onehop"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/serrors"
	libgrpc "github.com/scionproto/scion/go/pkg/grpc"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

type BeaconSenderFactory struct {
	Dialer libgrpc.Dialer
}

// creates a new sender
func (f *BeaconSenderFactory) NewSender(
	parentCtx context.Context,
	contextTimeout time.Duration,
	dstIA addr.IA,
	egIfId uint16,
	nextHop *net.UDPAddr,
) (beaconing.Sender, error) {
	addr := &onehop.Addr{
		IA:      dstIA,
		Egress:  egIfId,
		SVC:     addr.SvcCS,
		NextHop: nextHop,
	}
	grpcContext, cancelF := context.WithTimeout(parentCtx, contextTimeout)
	rpcStart := time.Now()

	conn, err := f.Dialer.Dial(grpcContext, addr)
	if err != nil {
		err = serrors.WrapStr("dialing gRPC conn", err)
		if grpcContext.Err() != nil {
			err = serrors.WrapStr("timed out getting beacon sender", err,
				"waited_for", time.Since(rpcStart))
		}
		cancelF()
		return nil, err
	}
	return &beaconSender{
		Conn:          conn,
		rpcCtx:        grpcContext,
		rpcCtxCancelF: cancelF,
		rpcStart:      rpcStart,
	}, nil
}

// Sender that can be used to send beacon segments
// Should be closed after use
type beaconSender struct {
	Conn          *grpc.ClientConn
	rpcCtx        context.Context
	rpcCtxCancelF context.CancelFunc
	rpcStart      time.Time
}

func (s beaconSender) Send(b *seg.PathSegment) error {
	client := cppb.NewSegmentCreationServiceClient(s.Conn)
	_, err := client.Beacon(s.rpcCtx,
		&cppb.BeaconRequest{
			Segment: seg.PathSegmentToPB(b),
		},
		libgrpc.RetryProfile...,
	)

	if err != nil && s.rpcCtx.Err() != nil {
		err = serrors.WrapStr("timed out waiting for RPC to complete", err,
			"waited_for", time.Since(s.rpcStart))
	}
	return err
}

// Cancels the rpcContext & closes the connection
func (s beaconSender) Close() error {
	s.rpcCtxCancelF()
	return s.Conn.Close()
}
