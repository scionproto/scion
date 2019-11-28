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
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/proto"
)

// ErrInvalidRequest indicates an invalid request.
var ErrInvalidRequest = serrors.New("invalid request")

// Resolver resolves segments that are locally cached.
type Resolver interface {
	// Resolve resolves a request set. It returns the segments that are locally
	// stored and the set of requests that have to be requested at a remote server.
	Resolve(ctx context.Context, segs Segments, req RequestSet) (Segments, RequestSet, error)
}

// LocalInfo provides information about which segments are always locally
// stored.
type LocalInfo interface {
	// IsSegLocal returns whether this segment should always be locally cached.
	IsSegLocal(ctx context.Context, src, dst addr.IA) (bool, error)
}

// NewResolver creates a new resolver with the given DB. The DB might be
// customized. E.g. a PS could inject a wrapper around GetNextQuery so that it
// always returns that the cache is up to date for segments that should be
// available local.
func NewResolver(DB pathdb.Read, revCache revcache.RevCache, localInfo LocalInfo) *DefaultResolver {
	return &DefaultResolver{
		DB:        DB,
		RevCache:  revCache,
		LocalInfo: localInfo,
	}
}

// DefaultResolver is the default resolver implementation.
type DefaultResolver struct {
	DB        pathdb.Read
	RevCache  revcache.RevCache
	LocalInfo LocalInfo
}

// Resolve resolves a request set. It returns the segments that are locally
// stored and the set of requests that have to be requested at a remote server.
func (r *DefaultResolver) Resolve(ctx context.Context, segs Segments,
	req RequestSet) (Segments, RequestSet, error) {

	var err error
	if req.resolveUp() {
		if segs, req, err = r.resolveUpSegs(ctx, segs, req); err != nil {
			return segs, req, err
		}
	}
	if req.resolveDown() {
		if segs, req, err = r.resolveDownSegs(ctx, segs, req); err != nil {
			return segs, req, err
		}
	}
	if zeroUpDownSegsCached(req, segs) {
		for i := range req.Cores {
			req.Cores[i].State = Loaded
		}
		return segs, req, nil
	}
	// If there are still up or down segments to request, or if there are no
	// core segments no more action can be done here.
	if !req.upDownResolved() || req.Cores.IsEmpty() {
		return segs, req, nil
	}
	// now resolve core segs:
	req.Cores, err = r.expandCores(segs, req)
	if err != nil {
		return segs, req, err
	}
	if req.Cores, err = r.resolveCores(ctx, req); err != nil {
		return segs, req, err
	}
	if len(req.Cores) == 0 {
		req.Cores = nil
	}
	for i, coreReq := range req.Cores {
		if local, err := r.LocalInfo.IsSegLocal(ctx, coreReq.Src, coreReq.Dst); err != nil {
			return segs, req, err
		} else if local {
			coreReq.State = Cached
		}
		if coreReq.State != Cached && coreReq.State != Fetched {
			continue
		}
		coreRes, err := r.DB.Get(ctx, &query.Params{
			StartsAt: []addr.IA{coreReq.Dst},
			EndsAt:   []addr.IA{coreReq.Src},
			SegTypes: []proto.PathSegType{proto.PathSegType_core},
		})
		if err != nil {
			return segs, req, err
		}
		allRev, err := r.allRevoked(ctx, coreRes)
		if err != nil {
			return segs, req, err
		}
		if allRev && coreReq.State != Fetched {
			req.Cores[i].State = Fetch
		} else {
			req.Cores[i].State = Loaded
		}
		segs.Core = append(segs.Core, coreRes.Segs()...)
	}
	return segs, req, nil
}

func (r *DefaultResolver) resolveUpSegs(ctx context.Context, segs Segments,
	req RequestSet) (Segments, RequestSet, error) {

	if req.Fetch && req.Up.State == Unresolved {
		req.Up.State = Fetch
		return segs, req, nil
	}
	var err error
	segs.Up, req.Up, err = r.resolveSegment(ctx, req.Up, false)
	return segs, req, err
}

func (r *DefaultResolver) resolveDownSegs(ctx context.Context, segs Segments,
	req RequestSet) (Segments, RequestSet, error) {

	if req.Fetch && req.Down.State == Unresolved {
		req.Down.State = Fetch
		return segs, req, nil
	}
	var err error
	segs.Down, req.Down, err = r.resolveSegment(ctx, req.Down, true)
	return segs, req, err
}

func (r *DefaultResolver) resolveSegment(ctx context.Context,
	req Request, consDir bool) (seg.Segments, Request, error) {

	if local, err := r.LocalInfo.IsSegLocal(ctx, req.Src, req.Dst); err != nil {
		return nil, req, err
	} else if local {
		req.State = Cached
	}
	if req.State == Unresolved {
		fetch, err := r.needsFetching(ctx, req)
		if err != nil || fetch {
			req.State = Fetch
			return nil, req, err
		}
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
	allRev, err := r.allRevoked(ctx, res)
	if err != nil {
		return res.Segs(), req, err
	}
	// because of revocations our cache is empty, so refetch
	if allRev && req.State == Unresolved {
		req.State = Fetch
		return nil, req, err
	}
	req.State = Loaded
	return res.Segs(), req, err
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
	if req.Fetch && coreReq.State == Unresolved {
		coreReq.State = Fetch
	}
	upIAs := segs.Up.FirstIAs()
	coreReqs := make([]Request, 0, len(upIAs))
	for _, upIA := range upIAs {
		if !upIA.Equal(coreReq.Dst) {
			coreReqs = append(coreReqs, Request{State: coreReq.State, Src: upIA, Dst: coreReq.Dst})
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
	if req.Fetch && coreReq.State == Unresolved {
		coreReq.State = Fetch
	}
	downIAs := segs.Down.FirstIAs()
	coreReqs := make([]Request, 0, len(downIAs))
	for _, downIA := range downIAs {
		if !downIA.Equal(coreReq.Src) {
			coreReqs = append(coreReqs,
				Request{State: coreReq.State, Src: coreReq.Src, Dst: downIA})
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
		return nil, serrors.WithCtx(ErrInvalidRequest,
			"req", req, "reason", "Core either src & dst should be wildcard or none.")
	}
	if req.Fetch && coreReq.State == Unresolved {
		coreReq.State = Fetch
	}
	upIAs := segs.Up.FirstIAs()
	downIAs := segs.Down.FirstIAs()
	var coreReqs []Request
	for _, upIA := range upIAs {
		for _, downIA := range downIAs {
			if !upIA.Equal(downIA) {
				coreReqs = append(coreReqs, Request{State: coreReq.State, Src: upIA, Dst: downIA})
			}
		}
	}
	return coreReqs, nil
}

// resolveCores returns cores requests classified with a state.
func (r *DefaultResolver) resolveCores(ctx context.Context,
	req RequestSet) (Requests, error) {

	needsFetching := make(map[Request]bool)
	for i, coreReq := range req.Cores {
		if coreReq.State == Fetched {
			req.Cores[i].State = Cached
			continue
		}
		if coreReq.State == Fetch {
			continue
		}
		coreFetch, ok := needsFetching[coreReq]
		if !ok {
			var err error
			if coreFetch, err = r.needsFetching(ctx, coreReq); err != nil {
				return req.Cores, err
			}
			needsFetching[coreReq] = coreFetch
		}
		if coreFetch {
			req.Cores[i].State = Fetch
		} else {
			req.Cores[i].State = Cached
		}
	}
	return req.Cores, nil
}

func (r *DefaultResolver) allRevoked(ctx context.Context,
	results query.Results) (bool, error) {

	segs := results.Segs()
	filtered, err := segs.FilterSegsErr(func(ps *seg.PathSegment) (bool, error) {
		return revcache.NoRevokedHopIntf(ctx, r.RevCache, ps)
	})
	if err != nil {
		return false, err
	}
	return len(segs) == 0 && filtered > 0, nil
}

func zeroUpDownSegsCached(r RequestSet, segs Segments) bool {
	return (!r.Up.IsZero() && r.Up.State == Loaded && len(segs.Up) == 0) ||
		(!r.Down.IsZero() && r.Down.State == Loaded && len(segs.Down) == 0)
}
