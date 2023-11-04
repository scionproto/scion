package happy

import (
	"context"
	"net"
	"sync"
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
	var wg sync.WaitGroup
	wg.Add(2)

	errs := [2]error{}
	successCh := make(chan struct{}, 2)

	go func() {
		defer log.HandlePanic()
		defer wg.Done()
		err := s.Connect.Send(abortCtx, b)
		if err == nil {
			successCh <- struct{}{}
			log.Info("Sent beacon via connect")
			cancel()
		} else {
			log.Info("Failed to send beacon via connect", "err", err)
		}
		errs[0] = err
	}()

	go func() {
		defer log.HandlePanic()
		defer wg.Done()
		select {
		case <-abortCtx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
		err := s.Grpc.Send(abortCtx, b)
		if err == nil {
			successCh <- struct{}{}
			log.Info("Sent beacon via gRPC")
			cancel()
		} else {
			log.Info("Failed to send beacon via gRPC", "err", err)
		}
		errs[1] = err
	}()

	wg.Wait()
	var combinedErrs serrors.List
	for _, err := range errs {
		if err != nil {
			combinedErrs = append(combinedErrs, err)
		}
	}
	// Only report error if both sends were unsuccessful.
	if len(combinedErrs) == 2 {
		return combinedErrs.ToError()
	}
	return nil
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
