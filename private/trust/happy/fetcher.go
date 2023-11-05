package happy

import (
	"context"
	"crypto/x509"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/trust"
)

// BeaconSenderFactory can be used to create beacon senders.
type Fetcher struct {
	Connect trust.Fetcher
	Grpc    trust.Fetcher
}

func (f Fetcher) Chains(ctx context.Context, query trust.ChainQuery,
	server net.Addr) ([][]*x509.Certificate, error) {

	abortCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(2)

	reps := [2][][]*x509.Certificate{}
	errs := [2]error{}

	go func() {
		defer log.HandlePanic()
		defer wg.Done()
		rep, err := f.Connect.Chains(abortCtx, query, server)
		if err == nil {
			reps[0] = rep
			log.Info("Received chains via connect")
			cancel()
		} else {
			log.Info("Failed to fetch chains via connect", "err", err)
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
		rep, err := f.Grpc.Chains(abortCtx, query, server)
		if err == nil {
			reps[0] = rep
			log.Info("Received chains via gRPC")
			cancel()
		} else {
			log.Info("Failed to fetch chains via gRPC", "err", err)
		}
		errs[1] = err
	}()

	wg.Wait()
	var combinedErrs serrors.List
	for i := range reps {
		if errs[i] != nil {
			combinedErrs = append(combinedErrs, errs[i])
			continue
		}
		return reps[i], nil
	}
	return nil, combinedErrs.ToError()
}

func (f Fetcher) TRC(ctx context.Context, id cppki.TRCID,
	server net.Addr) (cppki.SignedTRC, error) {

	abortCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(2)

	reps := [2]cppki.SignedTRC{}
	errs := [2]error{}

	go func() {
		defer log.HandlePanic()
		defer wg.Done()
		rep, err := f.Connect.TRC(abortCtx, id, server)
		if err == nil {
			reps[0] = rep
			log.Info("Received TRC via connect")
			cancel()
		} else {
			log.Info("Failed to fetch TRC via connect", "err", err)
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
		rep, err := f.Grpc.TRC(abortCtx, id, server)
		if err == nil {
			reps[0] = rep
			log.Info("Received TRC via gRPC")
			cancel()
		} else {
			log.Info("Failed to fetch TRC via gRPC", "err", err)
		}
		errs[1] = err
	}()

	wg.Wait()
	var combinedErrs serrors.List
	for i := range reps {
		if errs[i] != nil {
			combinedErrs = append(combinedErrs, errs[i])
			continue
		}
		return reps[i], nil
	}
	return cppki.SignedTRC{}, combinedErrs.ToError()
}
