// Copyright 2025 SCION Association, Anapaya Systems
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

package happy

import (
	"context"
	"errors"
	"net"

	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/control/config"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/connect/happy"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
)

// BeaconSenderFactory can be used to create beacon senders.
type BeaconSenderFactory struct {
	Connect beaconing.SenderFactory
	Grpc    beaconing.SenderFactory
}

// NewSender returns a beacon sender that can be used to send beacons to a remote CS.
func (f *BeaconSenderFactory) NewSender(
	ctx context.Context,
	dstIA addr.IA,
	egIfID uint16,
	nextHop *net.UDPAddr,
) (beaconing.Sender, error) {
	connectSender, err := f.Connect.NewSender(ctx, dstIA, egIfID, nextHop)
	if err != nil {
		return nil, serrors.Wrap("creating connect sender", err)
	}
	grpcSender, err := f.Grpc.NewSender(ctx, dstIA, egIfID, nextHop)
	if err != nil {
		return nil, serrors.Wrap("creating grpc sender", err)
	}
	return BeaconSender{
		Connect: connectSender,
		Grpc:    grpcSender,
	}, nil
}

type BeaconSender struct {
	Connect beaconing.Sender
	Grpc    beaconing.Sender
}

func (s BeaconSender) Send(ctx context.Context, b *seg.PathSegment) error {
	_, err := happy.Happy(
		ctx,
		happy.Call1[*seg.PathSegment, struct{}]{
			Call:   happy.NoReturn1[*seg.PathSegment](s.Connect.Send).Call,
			Input1: b,
			Typ:    "control_plane.v1.SegmentCreationService.Beacon",
		},
		happy.Call1[*seg.PathSegment, struct{}]{
			Call:   happy.NoReturn1[*seg.PathSegment](s.Grpc.Send).Call,
			Input1: b,
			Typ:    "control_plane.v1.SegmentCreationService.Beacon",
		},
		config.RpcClientConfig,
	)
	return err
}

func (s BeaconSender) Close() error {
	return errors.Join(s.Connect.Close(), s.Grpc.Close())
}

type Registrar struct {
	Connect beaconing.RPC
	Grpc    beaconing.RPC
}

func (r *Registrar) RegisterSegment(ctx context.Context, meta seg.Meta, remote net.Addr) error {
	_, err := happy.Happy(
		ctx,
		happy.Call2[seg.Meta, net.Addr, struct{}]{
			Call:   happy.NoReturn2[seg.Meta, net.Addr](r.Connect.RegisterSegment).Call,
			Input1: meta,
			Input2: remote,
			Typ:    "control_plane.v1.SegmentRegistrationService.SegmentsRegistration",
		},
		happy.Call2[seg.Meta, net.Addr, struct{}]{
			Call:   happy.NoReturn2[seg.Meta, net.Addr](r.Grpc.RegisterSegment).Call,
			Input1: meta,
			Input2: remote,
			Typ:    "control_plane.v1.SegmentRegistrationService.SegmentsRegistration",
		},
		config.RpcClientConfig,
	)
	return err
}
