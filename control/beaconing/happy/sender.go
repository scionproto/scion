package happy

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
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
	abortCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	connectCh := make(chan error, 1)
	grpcCh := make(chan error, 1)

	go func() {
		defer log.HandlePanic()
		err := s.Connect.Send(abortCtx, b)
		if abortCtx.Err() == nil {
			log.Debug("Sent beacon via connect")
		}
		connectCh <- err
	}()

	go func() {
		defer log.HandlePanic()
		time.Sleep(500 * time.Millisecond)
		err := s.Grpc.Send(abortCtx, b)
		if abortCtx.Err() == nil {
			log.Debug("Sent beacon via gRPC")
		}
		grpcCh <- err
	}()

	select {
	case err := <-connectCh:
		return err
	case err := <-grpcCh:
		return err
	}
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
