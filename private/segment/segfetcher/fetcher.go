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
	"math/rand"
	"net"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/segment/segfetcher/internal/metrics"
	"github.com/scionproto/scion/private/segment/seghandler"
)

const (
	minQueryInterval   = 2 * time.Second
	expirationLeadTime = 2 * time.Minute
)

// errors for metrics classification.
var (
	errFetch = serrors.New("fetching failed")
	errDB    = serrors.New("error with the db")
)

// ReplyHandler handles replies.
type ReplyHandler interface {
	Handle(ctx context.Context, recs seghandler.Segments,
		server net.Addr) *seghandler.ProcessedResult
}

// NewFetcherMetrics exposes the metrics constructor.
//
// XXX(roosd): This should be translated to the new metrics approach.
func NewFetcherMetrics(ns string) metrics.Fetcher {
	return metrics.NewFetcher(ns)
}

// Fetcher fetches, verifies and stores segments for a path segment request.
type Fetcher struct {
	Resolver     Resolver
	Requester    Requester
	ReplyHandler ReplyHandler
	PathDB       pathdb.DB
	// QueryInterval specifies after how much time segments should be
	// refetched at the remote server.
	QueryInterval time.Duration
	Metrics       metrics.Fetcher
}

// Fetch loads the requested segments from the path DB or requests them from a remote path server.
func (f *Fetcher) Fetch(ctx context.Context, reqs Requests, refresh bool) (Segments, error) {
	// Load local and cached segments from DB
	loadedSegs, fetchReqs, err := f.Resolver.Resolve(ctx, reqs, refresh)
	if err != nil {
		return Segments{}, serrors.JoinNoStack(errDB, err)
	}
	if len(fetchReqs) == 0 {
		return loadedSegs, nil
	}
	// Forward and cache any requests that were not local / cached
	fetchedSegs, err := f.Request(ctx, fetchReqs)
	if err != nil {
		err = serrors.JoinNoStack(errFetch, err)
	}
	return append(loadedSegs, fetchedSegs...), err
}

func (f *Fetcher) Request(ctx context.Context, reqs Requests) (Segments, error) {
	// Pass shorter context for requesting, such that we can reply even if a
	// request hangs.
	earlyCtx, cancel := earlyContext(ctx, 500*time.Millisecond)
	defer cancel()
	replies := f.Requester.Request(earlyCtx, reqs)
	return f.waitOnProcessed(ctx, replies)
}

func (f *Fetcher) waitOnProcessed(ctx context.Context,
	replies <-chan ReplyOrErr) (Segments, error) {

	var segs Segments
	logger := log.FromCtx(ctx)
	for reply := range replies {
		// TODO(lukedirtwalker): Should we do this in go routines?
		labels := metrics.RequestLabels{Result: metrics.ErrNotClassified}
		if reply.Err != nil {
			if serrors.IsTimeout(reply.Err) {
				labels.Result = metrics.ErrTimeout
			}
			f.Metrics.SegRequests(labels).Inc()
			continue
		}
		if len(reply.Segments) == 0 {
			f.Metrics.SegRequests(labels.WithResult(metrics.OkSuccess)).Inc()
			continue
		}
		r := f.ReplyHandler.Handle(ctx, replyToRecs(reply.Segments), reply.Peer)
		if err := r.Err(); err != nil {
			f.Metrics.SegRequests(labels.WithResult(metrics.ErrProcess)).Inc()
			return segs, serrors.Wrap("processing reply", err)
		}
		if len(r.VerificationErrors()) > 0 {
			log.FromCtx(ctx).Info("Errors during verification of segments/revocations",
				"number", len(r.VerificationErrors()))
			log.FromCtx(ctx).Debug("Error during verification of segments/revocations",
				"errors", r.VerificationErrors().ToError())
		}
		segs = append(segs, Segments(r.Stats().VerifiedSegs)...)
		nextQuery := f.nextQuery(segs)
		_, err := f.PathDB.InsertNextQuery(ctx, reply.Req.Src, reply.Req.Dst, nextQuery)
		if err != nil {
			logger.Info("NextQuery insertion failed", "err", err)
		}
		f.Metrics.SegRequests(labels.WithResult(metrics.OkSuccess)).Inc()
	}
	return segs, nil
}

// nextQuery decides the next time a query should be issued based on the
// received segments.
func (f *Fetcher) nextQuery(segs Segments) time.Time {
	// Determine the lead time for the latest segment expiration.
	// We want to request new segments before the last one has expired.
	expirationLead := maxSegmentExpiry(segs).Add(-expirationLeadTime)
	return f.nearestNextQueryTime(time.Now(), expirationLead)
}

// nearestNextQueryTime finds the nearest next query time in the interval spanned
// by the minimum and the configured query interval.
func (f *Fetcher) nearestNextQueryTime(now, nextQuery time.Time) time.Time {
	// Adding +-10% random jitter
	jitterPercent := time.Duration(rand.Intn(20) - 10)

	if earliest := now.Add(minQueryInterval); nextQuery.Before(earliest) {
		jitter := minQueryInterval * jitterPercent / 100
		return earliest.Add(jitter)
	}

	if latest := now.Add(f.QueryInterval); nextQuery.After(latest) {
		jitter := f.QueryInterval * jitterPercent / 100
		return latest.Add(jitter)
	}
	return nextQuery
}

func earlyContext(ctx context.Context, leadTime time.Duration) (context.Context, func()) {
	if deadline, ok := ctx.Deadline(); ok {
		// Only use early deadline if it is satisfiable and far enough in the
		// future. Cutting the request time too short is worse than timing
		// out during verification.
		if withLead := deadline.Add(-leadTime); time.Until(withLead) > leadTime {
			return context.WithDeadline(ctx, withLead)
		}
	}
	return ctx, func() {}
}

func maxSegmentExpiry(segs Segments) time.Time {
	var max time.Time
	for _, seg := range segs {
		if exp := seg.Segment.MinExpiry(); exp.After(max) {
			max = exp
		}
	}
	return max
}

func replyToRecs(reply []*seg.Meta) seghandler.Segments {
	return seghandler.Segments{
		Segs: reply,
	}
}
