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
	"github.com/scionproto/scion/go/proto"
)

// InvalidRequest indicates an invalid request.
const InvalidRequest = "Invalid request"

// Resolver resolves segments that are locally cached.
type Resolver interface {
	// Resolve resolves a request set. It returns the segments that are locally
	// stored and the set of requests that have to be requested at a remote server.
	Resolve(ctx context.Context, segs Segments, req RequestSet) (Segments, RequestSet, error)
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
func (r *DefaultResolver) Resolve(ctx context.Context, segs Segments,
	req RequestSet) (Segments, RequestSet, error) {

	var err error
	if !req.Up.IsZero() {
		if segs, req, err = r.resolveUpSegs(ctx, segs, req); err != nil {
			return segs, req, err
		}
	}
	if !req.Down.IsZero() {
		if segs, req, err = r.resolveDownSegs(ctx, segs, req); err != nil {
			return segs, req, err
		}
	}
	// If there are still up or down segments to request, or if there are no
	// core segments no more action can be done here.
	if !req.Up.IsZero() || !req.Down.IsZero() || req.Cores.IsEmpty() {
		return segs, req, nil
	}
	// now resolve core segs:
	req.Cores, err = r.expandCores(segs, req)
	if err != nil {
		return segs, req, err
	}
	var cachedReqs Requests
	if req.Cores, cachedReqs, err = r.resolveCores(ctx, req); err != nil {
		return segs, req, err
	}
	if len(req.Cores) == 0 {
		req.Cores = nil
	}
	if len(cachedReqs) > 0 {
		coreRes, err := r.DB.Get(ctx, &query.Params{
			StartsAt: cachedReqs.DstIAs(),
			EndsAt:   cachedReqs.SrcIAs(),
			SegTypes: []proto.PathSegType{proto.PathSegType_core},
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
	segs.Up, req.Up, err = r.resolveSegment(ctx, req.Up, false)
	return segs, req, err
}

func (r *DefaultResolver) resolveDownSegs(ctx context.Context, segs Segments,
	req RequestSet) (Segments, RequestSet, error) {

	var err error
	segs.Down, req.Down, err = r.resolveSegment(ctx, req.Down, true)
	return segs, req, err
}

func (r *DefaultResolver) resolveSegment(ctx context.Context,
	req Request, consDir bool) (seg.Segments, Request, error) {

	fetch, err := r.needsFetching(ctx, req)
	if err != nil || fetch {
		return nil, req, err
	}
	start, end := req.Src, req.Dst
	segType := proto.PathSegType_down
	if !consDir {
		start, end = end, start
		segType = proto.PathSegType_up
	}
	res, err := r.DB.Get(ctx, &query.Params{
		StartsAt: []addr.IA{start},
		EndsAt:   []addr.IA{end},
		SegTypes: []proto.PathSegType{segType},
	})
	if err != nil {
		return nil, req, err
	}
	return resultsToSegs(res), Request{}, err
}

func (r *DefaultResolver) needsFetching(ctx context.Context, req Request) (bool, error) {
	nq, err := r.DB.GetNextQuery(ctx, req.Src, req.Dst, nil)
	return time.Now().After(nq), err
}

func (r *DefaultResolver) expandCores(segs Segments, req RequestSet) ([]Request, error) {
	// Depending on the given request and the given segments we can determine
	// the shape of the request. If there are multiple core requests this must
	// be a core only request and therefore no expansion needs to be done. If
	// there are up segments but no down segments it means the request is
	// non-core to core, because the initial request could never have had any
	// down segments otherwise they would have been resolved by now. Similarly
	// if we have down segments but no up segments it means the request is core
	// to non-core. Finally if we have both up and down segments it is a
	// non-core to non-core request. Note that "core" and "non-core" does not
	// indicate anything about the location of the local AS. For example after
	// resolving up segments it could be that the resolver receives a request
	// core to non-core eventhough it is a non-core AS.
	switch {
	case len(req.Cores) > 1:
		// If the request already has multiple cores there is nothing to expand.
		return req.Cores, nil
	case len(segs.Up) == 0 && len(segs.Down) == 0:
		// If there is no up/down segments we can't expand anything.
		return req.Cores, nil
	case len(segs.Up) > 0 && len(segs.Down) == 0:
		// Non-core to core
		return r.expandNonCoreToCore(segs, req)
	case len(segs.Up) == 0 && len(segs.Down) > 0:
		// Core to non-core
		return r.expandCoreToNonCore(segs, req)
	default:
		// Non-core to non-core
		return r.expandNonCoreToNonCore(segs, req)
	}
}

// expandNonCoreToCore expands core segments for the non-core to core case.
func (r *DefaultResolver) expandNonCoreToCore(segs Segments,
	req RequestSet) ([]Request, error) {

	coreReq := req.Cores[0]
	if !coreReq.Src.IsWildcard() {
		// already resolved
		return req.Cores, nil
	}
	upIAs := segs.Up.FirstIAs()
	coreReqs := make([]Request, 0, len(upIAs))
	for _, upIA := range upIAs {
		if !upIA.Equal(coreReq.Dst) {
			coreReqs = append(coreReqs, Request{Src: upIA, Dst: coreReq.Dst})
		}
	}
	return coreReqs, nil
}

// expandCoreToNonCore expands core segments for the core to non-core case.
func (r *DefaultResolver) expandCoreToNonCore(segs Segments,
	req RequestSet) ([]Request, error) {

	coreReq := req.Cores[0]
	if !coreReq.Dst.IsWildcard() {
		// already resolved
		return req.Cores, nil
	}
	downIAs := segs.Down.FirstIAs()
	coreReqs := make([]Request, 0, len(downIAs))
	for _, downIA := range downIAs {
		if !downIA.Equal(coreReq.Src) {
			coreReqs = append(coreReqs, Request{Src: coreReq.Src, Dst: downIA})
		}
	}
	return coreReqs, nil
}

// expandNonCoreToNonCore expands core segments for the non-core to non-core case.
func (r *DefaultResolver) expandNonCoreToNonCore(segs Segments,
	req RequestSet) ([]Request, error) {

	coreReq := req.Cores[0]
	if !coreReq.Src.IsWildcard() && !coreReq.Dst.IsWildcard() {
		// already resolved
		return req.Cores, nil
	}
	if !coreReq.Src.IsWildcard() || !coreReq.Dst.IsWildcard() {
		return nil, common.NewBasicError(InvalidRequest, nil,
			"req", req, "reason", "Core either src & dst should be wildcard or none.")
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

// resolveCores returns cores that need to be requested and the ones which are
// already cached.
func (r *DefaultResolver) resolveCores(ctx context.Context,
	req RequestSet) (Requests, Requests, error) {

	var cachedReqs Requests
	remainingCores := req.Cores[:0]
	needsFetching := make(map[Request]bool)
	for _, coreReq := range req.Cores {
		coreFetch, ok := needsFetching[coreReq]
		if !ok {
			var err error
			if coreFetch, err = r.needsFetching(ctx, coreReq); err != nil {
				return remainingCores, cachedReqs, err
			}
			needsFetching[coreReq] = coreFetch
		}
		if coreFetch {
			remainingCores = append(remainingCores, coreReq)
		} else {
			cachedReqs = append(cachedReqs, coreReq)
		}
	}
	return remainingCores, cachedReqs, nil
}

func resultsToSegs(results query.Results) seg.Segments {
	segs := make(seg.Segments, 0, len(results))
	for _, res := range results {
		segs = append(segs, res.Seg)
	}
	return segs
}
