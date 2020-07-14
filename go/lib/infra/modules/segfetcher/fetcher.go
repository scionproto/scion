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
	"errors"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher/internal/metrics"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
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
	Handle(ctx context.Context, recs seghandler.Segments, server net.Addr,
		earlyTrigger <-chan struct{}) *seghandler.ProcessedResult
}

// FetcherConfig is the configuration for the fetcher.
type FetcherConfig struct {
	// QueryInterval specifies after how much time segments should be
	// refetched at the remote server.
	QueryInterval time.Duration
	// Verifier is the verifier to use.
	Verifier infra.Verifier
	// PathDB is the path db to use.
	PathDB pathdb.PathDB
	// RevCache is the revocation cache to use.
	RevCache revcache.RevCache
	// RequestAPI is the request api to use.
	RequestAPI RequestAPI
	// DstProvider provides destinations to fetch segments from
	DstProvider DstProvider
	// MetricsNamespace is the namespace used for metrics.
	MetricsNamespace string
	// LocalInfo provides information about local segments.
	LocalInfo LocalInfo
}

// New creates a new fetcher from the configuration.
func (cfg FetcherConfig) New() *Fetcher {
	return &Fetcher{
		Resolver:  NewResolver(cfg.PathDB, cfg.RevCache, cfg.LocalInfo),
		Requester: &DefaultRequester{API: cfg.RequestAPI, DstProvider: cfg.DstProvider},
		ReplyHandler: &seghandler.Handler{
			Verifier: &seghandler.DefaultVerifier{Verifier: cfg.Verifier},
			Storage:  &seghandler.DefaultStorage{PathDB: cfg.PathDB, RevCache: cfg.RevCache},
		},
		PathDB:        cfg.PathDB,
		QueryInterval: cfg.QueryInterval,
		metrics:       metrics.NewFetcher(cfg.MetricsNamespace),
	}
}

// Fetcher fetches, verifies and stores segments for a path segment request.
type Fetcher struct {
	Resolver      Resolver
	Requester     Requester
	ReplyHandler  ReplyHandler
	PathDB        pathdb.PathDB
	QueryInterval time.Duration
	metrics       metrics.Fetcher
}

// Fetch loads the requested segments from the path DB or requests them from a remote path server.
func (f *Fetcher) Fetch(ctx context.Context, reqs Requests, refresh bool) (Segments, error) {
	// Load local and cached segments from DB
	loadedSegs, fetchReqs, err := f.Resolver.Resolve(ctx, reqs, refresh)
	if err != nil {
		return Segments{}, serrors.Wrap(errDB, err)
	}
	if len(fetchReqs) == 0 {
		return loadedSegs, nil
	}
	// Forward and cache any requests that were not local / cached
	fetchedSegs, err := f.Request(ctx, fetchReqs)
	if err != nil {
		return Segments{}, serrors.Wrap(errFetch, err)
	}
	return append(loadedSegs, fetchedSegs...), nil
}

func (f *Fetcher) Request(ctx context.Context, reqs Requests) (Segments, error) {
	// XXX(lukedirtwalker): Optimally we wouldn't need a different timeout
	// here. The problem is that revocations can't be differentiated from
	// timeouts. And having 10s timeouts plays really bad together with
	// revocations. See also: https://github.com/scionproto/scion/issues/3052
	reqCtx, cancelF := context.WithTimeout(ctx, 3*time.Second)
	defer cancelF()
	replies := f.Requester.Request(reqCtx, reqs)
	return f.waitOnProcessed(ctx, replies)
}

func (f *Fetcher) waitOnProcessed(ctx context.Context,
	replies <-chan ReplyOrErr) (Segments, error) {

	var segs Segments
	logger := log.FromCtx(ctx)
	for reply := range replies {
		// TODO(lukedirtwalker): Should we do this in go routines?
		labels := metrics.RequestLabels{Result: metrics.ErrNotClassified}
		if errors.Is(reply.Err, ErrNotReachable) {
			log.FromCtx(ctx).Info("Request for unreachable dest ignored",
				"req", reply.Req, "err", reply.Err)
			f.metrics.SegRequests(labels.WithResult(metrics.OkSuccess)).Inc()
			continue
		}
		if reply.Err != nil {
			if serrors.IsTimeout(reply.Err) {
				labels.Result = metrics.ErrTimeout
			}
			f.metrics.SegRequests(labels).Inc()
			return segs, reply.Err
		}
		if reply.Reply == nil || reply.Reply.Recs == nil {
			f.metrics.SegRequests(labels.WithResult(metrics.OkSuccess)).Inc()
			continue
		}
		r := f.ReplyHandler.Handle(ctx, replyToRecs(reply.Reply), reply.Peer, nil)
		select {
		case <-r.FullReplyProcessed():
			defer f.metrics.UpdateRevocation(r.Stats().RevStored(),
				r.Stats().RevDBErrs(), r.Stats().RevVerifyErrors())
			if err := r.Err(); err != nil {
				f.metrics.SegRequests(labels.WithResult(metrics.ErrProcess)).Inc()
				return segs, err
			}
			if len(r.VerificationErrors()) > 0 {
				log.FromCtx(ctx).Info("Error during verification of segments/revocations",
					"errors", r.VerificationErrors().ToError())
			}
			segs = append(segs, segsWithHPToSegs(r.Stats().VerifiedSegs)...)
			nextQuery := f.nextQuery(segs)
			_, err := f.PathDB.InsertNextQuery(ctx, reply.Req.Src, reply.Req.Dst, nil, nextQuery)
			if err != nil {
				logger.Info("NextQuery insertion failed", "err", err)
			}
			f.metrics.SegRequests(labels.WithResult(metrics.OkSuccess)).Inc()
		case <-ctx.Done():
			f.metrics.SegRequests(labels.WithResult(metrics.ErrTimeout)).Inc()
			return segs, ctx.Err()
		}
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
	if earliest := now.Add(minQueryInterval); nextQuery.Before(earliest) {
		return earliest
	}
	if latest := now.Add(f.QueryInterval); nextQuery.After(latest) {
		return latest
	}
	return nextQuery
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

func replyToRecs(reply *path_mgmt.SegReply) seghandler.Segments {
	return seghandler.Segments{
		Segs:      reply.Recs.Recs,
		SRevInfos: reply.Recs.SRevInfos,
	}
}

func segsWithHPToSegs(segsWithHP []*seghandler.SegWithHP) Segments {
	segs := make(Segments, 0, len(segsWithHP))
	for _, seg := range segsWithHP {
		segs = append(segs, seg.Seg)
	}
	return segs
}
