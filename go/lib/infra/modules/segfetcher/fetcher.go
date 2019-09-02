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
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/revcache"
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
	// VerificationFactory is the verification factory to use.
	VerificationFactory infra.VerificationFactory
	// ASInspector is the as inspector to use.
	ASInspector infra.ASInspector
	// PathDB is the path db to use.
	PathDB pathdb.PathDB
	// RevCache is the revocation cache to use.
	RevCache revcache.RevCache
	// RequestAPI is the request api to use.
	RequestAPI RequestAPI
	// DstProvider provides destinations to fetch segments from
	DstProvider DstProvider
	// Validator is used to validate requests.
	Validator Validator
	// Splitter is used to split requests.
	Splitter Splitter
	// SciondMode enables sciond mode, this means it uses the local CS to fetch
	// crypto material and considers revocations in the path lookup.
	SciondMode bool
}

// New creates a new fetcher from the configuration.
func (cfg FetcherConfig) New() *Fetcher {
	return &Fetcher{
		Validator: cfg.Validator,
		Splitter:  cfg.Splitter,
		Resolver:  NewResolver(cfg.PathDB, cfg.RevCache, !cfg.SciondMode),
		Requester: &DefaultRequester{API: cfg.RequestAPI, DstProvider: cfg.DstProvider},
		ReplyHandler: &seghandler.Handler{
			Verifier: &seghandler.DefaultVerifier{Verifier: cfg.VerificationFactory.NewVerifier()},
			Storage:  &seghandler.DefaultStorage{PathDB: cfg.PathDB, RevCache: cfg.RevCache},
		},
		PathDB:                cfg.PathDB,
		QueryInterval:         cfg.QueryInterval,
		NextQueryCleaner:      NextQueryCleaner{PathDB: cfg.PathDB},
		CryptoLookupAtLocalCS: cfg.SciondMode,
	}
}

// Fetcher fetches, verifies and stores segments for a given path request.
type Fetcher struct {
	Validator             Validator
	Splitter              Splitter
	Resolver              Resolver
	Requester             Requester
	ReplyHandler          ReplyHandler
	PathDB                pathdb.PathDB
	QueryInterval         time.Duration
	NextQueryCleaner      NextQueryCleaner
	CryptoLookupAtLocalCS bool
}

// FetchSegs fetches the required segments to build a path between src and dst
// of the request. First the request is validated and then depending on the
// cache the segments are fetched from the remote server.
func (f *Fetcher) FetchSegs(ctx context.Context, req Request) (Segments, error) {
	if f.Validator != nil {
		if err := f.Validator.Validate(ctx, req); err != nil {
			return Segments{}, err
		}
	}
	reqSet, err := f.Splitter.Split(ctx, req)
	if err != nil {
		return Segments{}, err
	}
	var segs Segments
	i := 0
	for {
		log.FromCtx(ctx).Trace("Request to process",
			"req", reqSet, "segs", segs, "iteration", i+1)
		segs, reqSet, err = f.Resolver.Resolve(ctx, segs, reqSet)
		if err != nil {
			return Segments{}, err
		}
		log.FromCtx(ctx).Trace("After resolving",
			"req", reqSet, "segs", segs, "iteration", i+1)
		if reqSet.IsEmpty() {
			break
		}
		if i > 3 {
			log.FromCtx(ctx).Error("No convergence in lookup", "iteration", i+1)
			return segs, common.NewBasicError("Segment lookup doesn't converge", nil,
				"iterations", i+1)
		}
		// XXX(lukedirtwalker): Optimally we wouldn't need a different timeout
		// here. The problem is that revocations can't be differentiated from
		// timeouts. And having 10s timeouts plays really bad together with
		// revocations. See also: https://github.com/scionproto/scion/issues/3052
		reqCtx, cancelF := context.WithTimeout(ctx, 3*time.Second)
		replies := f.Requester.Request(reqCtx, reqSet)
		// TODO(lukedirtwalker): We need to have early trigger for the last request.
		if err := f.waitOnProcessed(ctx, replies); err != nil {
			cancelF()
			return Segments{}, err
		}
		cancelF()
	}
	return segs, nil
}

func (f *Fetcher) waitOnProcessed(ctx context.Context, replies <-chan ReplyOrErr) error {
	logger := log.FromCtx(ctx)
	for reply := range replies {
		// TODO(lukedirtwalker): Should we do this in go routines?
		if reply.Err != nil {
			return reply.Err
		}
		if reply.Reply == nil || reply.Reply.Recs == nil {
			continue
		}
		r := f.ReplyHandler.Handle(ctx, replyToRecs(reply.Reply), f.verifyServer(reply), nil)
		select {
		case <-r.FullReplyProcessed():
			if err := r.Err(); err != nil {
				return err
			}
			queryInt := f.QueryInterval
			for _, rev := range r.VerifiedRevs() {
				revInfo, err := rev.RevInfo()
				if err != nil {
					logger.Warn("Failed to extract rev info from verified rev",
						"err", err, "rev", rev)
					continue
				}
				f.NextQueryCleaner.ResetQueryCache(ctx, revInfo)
			}
			// TODO(lukedirtwalker): make the short interval configurable
			if r.VerifiedSegs() <= 0 {
				queryInt = 2 * time.Second
			}
			_, err := f.PathDB.InsertNextQuery(ctx, reply.Req.Src, reply.Req.Dst, nil,
				time.Now().Add(queryInt))
			if err != nil {
				logger.Warn("Failed to insert next query", "err", err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (f *Fetcher) verifyServer(reply ReplyOrErr) net.Addr {
	if f.CryptoLookupAtLocalCS {
		return nil
	}
	return reply.Peer
}

func replyToRecs(reply *path_mgmt.SegReply) seghandler.Segments {
	return seghandler.Segments{
		Segs:      reply.Recs.Recs,
		SRevInfos: reply.Recs.SRevInfos,
	}
}
