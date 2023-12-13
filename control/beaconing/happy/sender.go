package happy

import (
	"context"
	"net"

	"github.com/scionproto/scion/control/beaconing"
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
	egIfId uint16,
	nextHop *net.UDPAddr,
) (beaconing.Sender, error) {
	connectSender, err := f.Connect.NewSender(ctx, dstIA, egIfId, nextHop)
	if err != nil {
		return nil, err
	}
	grpcSender, err := f.Grpc.NewSender(ctx, dstIA, egIfId, nextHop)
	if err != nil {
		return nil, err
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
			Call:   happy.NoReturn1[*seg.PathSegment](s.Connect.Send).Call,
			Input1: b,
			Typ:    "control_plane.v1.SegmentCreationService.Beacon",
		},
	)
	return err
}

func (s BeaconSender) Close() error {
	var errs serrors.List
	if err := s.Connect.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := s.Grpc.Close(); err != nil {
		errs = append(errs, err)
	}
	return errs.ToError()
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
			Call:   happy.NoReturn2[seg.Meta, net.Addr](r.Connect.RegisterSegment).Call,
			Input1: meta,
			Input2: remote,
			Typ:    "control_plane.v1.SegmentRegistrationService.SegmentsRegistration",
		},
	)
	return err
}
