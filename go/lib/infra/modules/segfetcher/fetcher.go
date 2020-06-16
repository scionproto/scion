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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
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
	errValidate = serrors.New("request validation failed")
	errFetch    = serrors.New("fetching failed")
	errDB       = serrors.New("error with the db")
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
	// LocalIA is the IA this process is in.
	LocalIA addr.IA
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
	// Splitter is used to split requests.
	Splitter Splitter
	// MetricsNamespace is the namespace used for metrics.
	MetricsNamespace string
	// LocalInfo provides information about local segments.
	LocalInfo LocalInfo
}

// New creates a new fetcher from the configuration.
func (cfg FetcherConfig) New() *Fetcher {
	return &Fetcher{
		Splitter:  cfg.Splitter,
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

// Fetcher fetches, verifies and stores segments for a given path request.
type Fetcher struct {
	Splitter      Splitter
	Resolver      Resolver
	Requester     Requester
	ReplyHandler  ReplyHandler
	PathDB        pathdb.PathDB
	QueryInterval time.Duration
	metrics       metrics.Fetcher
}

// FetchSegs fetches the required segments to build a path between src and dst
// of the request. First the request is validated and then depending on the
// cache the segments are fetched from the remote server.
func (f *Fetcher) FetchSegs(ctx context.Context, req Request) (Segments, error) {
	reqSet, err := f.Splitter.Split(ctx, req)
	if err != nil {
		return Segments{}, err
	}
	var segs Segments
	for i := 0; i < 3; i++ {
		log.FromCtx(ctx).Debug("Request to process", "req", reqSet, "segs", segs, "iteration", i+1)
		segs, reqSet, err = f.Resolver.Resolve(ctx, segs, reqSet)
		if err != nil {
			return Segments{}, serrors.Wrap(errDB, err)
		}
		log.FromCtx(ctx).Debug("After resolving", "req", reqSet, "segs", segs, "iteration", i+1)
		if reqSet.IsLoaded() {
			break
		}
		// in 3 iteration (i==2) everything should be resolved, worst case:
		// 1 iteration: up & down segment fetched.
		// 2 iteration: up & down resolved, core fetched.
		// 3 iteration: core resolved -> done.
		if i >= 2 {
			return segs, common.NewBasicError(
				"Segment lookup not done in expected amount of iterations (implementation bug)",
				nil, "iterations", i+1)
		}
		// XXX(lukedirtwalker): Optimally we wouldn't need a different timeout
		// here. The problem is that revocations can't be differentiated from
		// timeouts. And having 10s timeouts plays really bad together with
		// revocations. See also: https://github.com/scionproto/scion/issues/3052
		reqCtx, cancelF := context.WithTimeout(ctx, 3*time.Second)
		reqCtx = log.CtxWith(reqCtx, log.FromCtx(ctx))
		replies := f.Requester.Request(reqCtx, reqSet)
		// TODO(lukedirtwalker): We need to have early trigger for the last request.
		if reqSet, err = f.waitOnProcessed(ctx, replies, reqSet); err != nil {
			cancelF()
			return Segments{}, err
		}
		cancelF()
	}
	return segs, nil
}

func (f *Fetcher) waitOnProcessed(ctx context.Context, replies <-chan ReplyOrErr,
	reqSet RequestSet) (RequestSet, error) {

	logger := log.FromCtx(ctx)
	for reply := range replies {
		// TODO(lukedirtwalker): Should we do this in go routines?
		labels := metrics.RequestLabels{Result: metrics.ErrNotClassified}
		if errors.Is(reply.Err, ErrNotReachable) {
			log.FromCtx(ctx).Info("Request for unreachable dest ignored",
				"req", reply.Req, "err", reply.Err)
			f.metrics.SegRequests(labels.WithResult(metrics.OkSuccess)).Inc()
			reqSet = updateRequestState(reqSet, reply.Req, Loaded)
			continue
		}
		if reply.Err != nil {
			if serrors.IsTimeout(reply.Err) {
				labels.Result = metrics.ErrTimeout
			}
			f.metrics.SegRequests(labels).Inc()
			return reqSet, reply.Err
		}
		if reply.Reply == nil || reply.Reply.Recs == nil {
			f.metrics.SegRequests(labels.WithResult(metrics.OkSuccess)).Inc()
			reqSet = updateRequestState(reqSet, reply.Req, Fetched)
			continue
		}
		r := f.ReplyHandler.Handle(ctx, replyToRecs(reply.Reply), reply.Peer, nil)
		select {
		case <-r.FullReplyProcessed():
			defer f.metrics.UpdateRevocation(r.Stats().RevStored(),
				r.Stats().RevDBErrs(), r.Stats().RevVerifyErrors())
			if err := r.Err(); err != nil {
				f.metrics.SegRequests(labels.WithResult(metrics.ErrProcess)).Inc()
				return reqSet, err
			}
			if len(r.VerificationErrors()) > 0 {
				log.FromCtx(ctx).Info("Error during verification of segments/revocations",
					"errors", r.VerificationErrors().ToError())
			}
			reqSet = updateRequestState(reqSet, reply.Req, Fetched)
			nextQuery := f.nextQuery(r.Stats().VerifiedSegs)
			_, err := f.PathDB.InsertNextQuery(ctx, reply.Req.Src, reply.Req.Dst, nil, nextQuery)
			if err != nil {
				logger.Info("NextQuery insertion failed", "err", err)
			}
			f.metrics.SegRequests(labels.WithResult(metrics.OkSuccess)).Inc()
		case <-ctx.Done():
			f.metrics.SegRequests(labels.WithResult(metrics.ErrTimeout)).Inc()
			return reqSet, ctx.Err()
		}
	}
	return reqSet, nil
}

// nextQuery decides the next time a query should be issued based on the
// received segments.
func (f *Fetcher) nextQuery(segs []*seghandler.SegWithHP) time.Time {
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

func maxSegmentExpiry(segs []*seghandler.SegWithHP) time.Time {
	var max time.Time
	for _, seg := range segs {
		if exp := seg.Seg.Segment.MinExpiry(); exp.After(max) {
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

func updateRequestState(reqSet RequestSet, reqToUpdate Request, newState RequestState) RequestSet {
	if reqSet.Up.EqualAddr(reqToUpdate) {
		reqSet.Up.State = newState
	} else if reqSet.Down.EqualAddr(reqToUpdate) {
		reqSet.Down.State = newState
	} else {
		for i, coreReq := range reqSet.Cores {
			if coreReq.EqualAddr(reqToUpdate) {
				reqSet.Cores[i].State = newState
			}
		}
	}
	return reqSet
}
