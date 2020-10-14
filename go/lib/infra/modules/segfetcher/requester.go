// Copyright 2019 Anapaya Systems
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

package segfetcher

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
)

// ErrNotReachable indicates that the destination is not reachable from this process.
var ErrNotReachable = serrors.New("remote not reachable")

// RPC is used to fetch segments from a remote.
type RPC interface {
	Segments(ctx context.Context, req Request, dst net.Addr) ([]*seg.Meta, error)
}

// DstProvider provides the destination for a segment lookup including the path.
type DstProvider interface {
	Dst(context.Context, Request) (net.Addr, error)
}

// ReplyOrErr is a seg reply or an error for the given request.
type ReplyOrErr struct {
	Req      Request
	Segments []*seg.Meta
	Peer     net.Addr
	Err      error
}

// Requester requests segments.
type Requester interface {
	Request(ctx context.Context, req Requests) <-chan ReplyOrErr
}

// DefaultRequester requests all segments that can be requested from a request set.
type DefaultRequester struct {
	RPC         RPC
	DstProvider DstProvider
	// TimeoutFactor is the percentage of the total timeout available for a segment request
	// that is allocated to the next try.
	TimeoutFactor float64
	MaxTries      int
}

// Request all requests in the request set
func (r *DefaultRequester) Request(ctx context.Context, reqs Requests) <-chan ReplyOrErr {
	var wg sync.WaitGroup

	replies := make(chan ReplyOrErr, len(reqs))
	wg.Add(len(reqs))
	go func() {
		defer log.HandlePanic()
		wg.Wait()
		close(replies)
	}()
	for i := range reqs {
		i := i
		go func() {
			defer log.HandlePanic()
			defer wg.Done()
			r.requestWorker(ctx, reqs, i, replies)
		}()
	}
	return replies
}

// requestWorker processes request i of reqs, and writes the result to the replies channel.
func (r *DefaultRequester) requestWorker(ctx context.Context, reqs Requests, i int,
	replies chan<- ReplyOrErr) {

	req := reqs[i]
	span, ctx := opentracing.StartSpanFromContext(ctx, "segfetcher.requester",
		opentracing.Tags{
			"req.src":      req.Src.String(),
			"req.dst":      req.Dst.String(),
			"req.seg_type": req.SegType.String(),
		},
	)
	defer span.Finish()

	logger := log.FromCtx(ctx).New("req_id", log.NewDebugID(), "request", req)
	ctx = log.CtxWith(ctx, logger)

	try := func(ctx context.Context) ([]*seg.Meta, net.Addr, error) {
		tryCtx, cancel := r.tryDeadline(ctx)
		defer cancel()
		dst, err := r.DstProvider.Dst(tryCtx, req)
		if err != nil {
			return nil, nil, err
		}
		segs, err := r.RPC.Segments(tryCtx, req, dst)
		if err != nil {
			return nil, dst, err
		}
		return segs, dst, nil
	}
	for tryIndex := 0; ctx.Err() == nil && tryIndex < r.maxTries(); tryIndex++ {
		segs, peer, err := try(ctx)
		if err != nil {
			logger.Debug("Segment lookup failed", "try", tryIndex+1, "peer", peer,
				"err", err)
			continue
		}
		replies <- ReplyOrErr{Req: req, Segments: segs, Peer: peer}
		return
	}
	err := ctx.Err()
	if err == nil {
		err = serrors.New("no attempts left")
	}
	replies <- ReplyOrErr{Req: req, Err: err}
}

func (r *DefaultRequester) tryDeadline(ctx context.Context) (context.Context, func()) {
	if deadline, ok := ctx.Deadline(); r.TimeoutFactor != 0 && ok {
		timeout := time.Duration(float64(time.Until(deadline)) * r.TimeoutFactor)
		return context.WithTimeout(ctx, timeout)

	}
	return ctx, func() {}
}

func (r *DefaultRequester) maxTries() int {
	if r.MaxTries == 0 {
		return 3
	}
	return r.MaxTries
}
