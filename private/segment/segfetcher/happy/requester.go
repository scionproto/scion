package happy

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/segment/segfetcher"
)

// Requester fetches segments from a remote using gRPC.
type Requester struct {
	Connect segfetcher.RPC
	Grpc    segfetcher.RPC
}

func (f *Requester) Segments(ctx context.Context, req segfetcher.Request,
	server net.Addr) (segfetcher.SegmentsReply, error) {

	abortCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(2)

	reps := [2]segfetcher.SegmentsReply{}
	errs := [2]error{}

	go func() {
		defer log.HandlePanic()
		defer wg.Done()
		rep, err := f.Connect.Segments(abortCtx, req, server)
		if err == nil {
			reps[0] = rep
			log.Info("Received segments via connect")
			cancel()
		} else {
			log.Info("Failed to fetch segments via connect", "err", err)
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
		rep, err := f.Grpc.Segments(abortCtx, req, server)
		if err == nil {
			reps[0] = rep
			log.Info("Received segments via gRPC")
			cancel()
		} else {
			log.Info("Failed to fetch segments via gRPC", "err", err)
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
	return segfetcher.SegmentsReply{}, combinedErrs.ToError()
}
