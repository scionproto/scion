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
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
)

// InvalidRequest indicates an invalid request.
const InvalidRequest = "Invalid request set"

// Resolver resolves requests in a request set and removes locally cached data.
type Resolver interface {
	Resolve(ctx context.Context, req RequestSet) (Segments, RequestSet, error)
}

// NewResolver creates a new resolver with the given DB. The DB might be
// customized. E.g. a PS could inject a wrapper around GetNextQuery so that it
// always returns that the cache is up to date for segments that should be
// available local.
func NewResolver(DB pathdb.Read) *DefaultResolver {
	return &DefaultResolver{
		DB: DB,
	}
}

// DefaultResolver is the default resolver implementation.
type DefaultResolver struct {
	DB pathdb.Read
}

// Resolve resolves a request set. It returns the segments that are locally
// stored and the set of requests that have to be requested at a remote server.
func (r *DefaultResolver) Resolve(ctx context.Context,
	req RequestSet) (Segments, RequestSet, error) {

	var segs Segments
	var err error
	if !req.Up.IsZero() {
		segs, req, err = r.resolveUpSegs(ctx, segs, req)
		if !req.Up.IsZero() || err != nil {
			return segs, req, err
		}
	}
	if !req.Down.IsZero() {
		segs, req, err = r.resolveDownSegs(ctx, segs, req)
		if !req.Down.IsZero() || err != nil {
			return segs, req, err
		}
	}
	if req.Cores.IsEmpty() {
		return segs, req, nil
	}
	// now resolve core segs:
	req.Cores, err = r.expandCores(segs, req)
	if err != nil {
		return segs, req, err
	}
	var cachedReqs Requests
	remainingCores := req.Cores[:0]
	needsFetching := make(map[addr.IA]bool)
	for _, coreReq := range req.Cores {
		coreFetch, ok := needsFetching[coreReq.Dst]
		if !ok {
			coreFetch, err = r.needsFetching(ctx, coreReq.Dst)
			if err != nil {
				return segs, req, err
			}
			needsFetching[coreReq.Dst] = coreFetch
		}
		if coreFetch {
			remainingCores = append(remainingCores, coreReq)
		} else {
			cachedReqs = append(cachedReqs, coreReq)
		}
	}
	req.Cores = remainingCores
	if len(req.Cores) == 0 {
		req.Cores = nil
	}
	if len(cachedReqs) > 0 {
		coreRes, err := r.DB.Get(ctx, &query.Params{
			StartsAt: cachedReqs.DstIAs(),
			EndsAt:   cachedReqs.SrcIAs(),
		})
		if err != nil {
			return segs, req, err
		}
		segs.Core = resultsToSegs(coreRes)
	}
	return segs, req, nil
}

func (r *DefaultResolver) resolveUpSegs(ctx context.Context, segs Segments,
	req RequestSet) (Segments, RequestSet, error) {

	var err error
	segs.Up, req.Up, err = r.resolveUpDown(ctx, req.Up, false)
	return segs, req, err
}

func (r *DefaultResolver) resolveDownSegs(ctx context.Context, segs Segments,
	req RequestSet) (Segments, RequestSet, error) {

	var err error
	segs.Down, req.Down, err = r.resolveUpDown(ctx, req.Down, true)
	return segs, req, err
}

func (r *DefaultResolver) resolveUpDown(ctx context.Context,
	req Request, consDir bool) (seg.Segments, Request, error) {

	fetch, err := r.needsFetching(ctx, req.Dst)
	if err != nil || fetch {
		return nil, req, err
	}
	start, end := req.Src, req.Dst
	if !consDir {
		start, end = end, start
	}
	res, err := r.DB.Get(ctx, &query.Params{
		StartsAt: []addr.IA{start},
		EndsAt:   []addr.IA{end},
	})
	if err != nil {
		return nil, req, err
	}
	return resultsToSegs(res), Request{}, err
}

func (r *DefaultResolver) needsFetching(ctx context.Context, dst addr.IA) (bool, error) {
	nq, err := r.DB.GetNextQuery(ctx, dst)
	if err != nil || nq == nil {
		return true, err
	}
	return time.Now().After(*nq), nil
}

func (r *DefaultResolver) expandCores(segs Segments, req RequestSet) ([]Request, error) {
	coreReq := req.Cores[0]
	switch {
	case len(req.Cores) > 1:
		return req.Cores, nil
	case len(segs.Up) == 0 && len(segs.Down) == 0:
		return req.Cores, nil
	case len(segs.Up) > 0 && len(segs.Down) == 0:
		if !coreReq.Src.IsWildcard() {
			return nil, common.NewBasicError(InvalidRequest, nil,
				"req", req, "reason", "Core src should be wildcard.")
		}
		upIAs := segs.Up.FirstIAs()
		coreReqs := make([]Request, 0, len(upIAs))
		for _, upIA := range upIAs {
			if !upIA.Equal(coreReq.Dst) {
				coreReqs = append(coreReqs, Request{Src: upIA, Dst: coreReq.Dst})
			}
		}
		return coreReqs, nil
	case len(segs.Up) == 0 && len(segs.Down) > 0:
		if !coreReq.Dst.IsWildcard() {
			return nil, common.NewBasicError(InvalidRequest, nil,
				"req", req, "reason", "Core dst should be wildcard.")
		}
		downIAs := segs.Down.FirstIAs()
		coreReqs := make([]Request, 0, len(downIAs))
		for _, downIA := range downIAs {
			if !downIA.Equal(coreReq.Src) {
				coreReqs = append(coreReqs, Request{Src: coreReq.Src, Dst: downIA})
			}
		}
		return coreReqs, nil
	default:
		if !coreReq.Src.IsWildcard() || !coreReq.Dst.IsWildcard() {
			return nil, common.NewBasicError(InvalidRequest, nil,
				"req", req, "reason", "Core src & dst should be wildcard.")
		}
		upIAs := segs.Up.FirstIAs()
		downIAs := segs.Down.FirstIAs()
		var coreReqs []Request
		for _, upIA := range upIAs {
			for _, downIA := range downIAs {
				if !upIA.Equal(downIA) {
					coreReqs = append(coreReqs, Request{Src: upIA, Dst: downIA})
				}
			}
		}
		return coreReqs, nil
	}
}

func resultsToSegs(results query.Results) seg.Segments {
	segs := make(seg.Segments, 0, len(results))
	for _, res := range results {
		segs = append(segs, res.Seg)
	}
	return segs
}
