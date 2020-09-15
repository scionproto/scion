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
)

// ErrInvalidRequest indicates an invalid request.
var ErrInvalidRequest = serrors.New("invalid request")

// Resolver resolves segments that are locally cached.
type Resolver interface {
	// Resolve resolves requests. It loads the segments that are locally available
	// from the DB and returns the set of requests that have to be requested at a
	// remote server.
	Resolve(ctx context.Context, reqs Requests, refresh bool) (Segments, Requests, error)
}

// LocalInfo provides information about which segments are always locally
// stored.
type LocalInfo interface {
	// IsSegLocal returns whether the requested segment is always locally stored.
	IsSegLocal(req Request) bool
}

// NewResolver creates a new resolver with the given DB.
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

// Resolve resolves requests. It loads the segments that are locally available
// from the DB and returns the set of requests that have to be requested at a
// remote server.
func (r *DefaultResolver) Resolve(ctx context.Context,
	reqs Requests, refresh bool) (Segments, Requests, error) {

	var segs Segments
	var fetchReqs Requests
	for i := range reqs {
		segsi, err := r.resolveSegment(ctx, reqs[i], refresh)
		if err != nil {
			return nil, nil, err
		}
		if segsi != nil {
			segs = append(segs, segsi...)
		} else {
			fetchReqs = append(fetchReqs, reqs[i])
		}
	}
	return segs, fetchReqs, nil
}

// resolveSegment loads the segments for this request from the DB.
// Returns nil if the segments are not local information and are not
// available/up to date from the cache.
func (r *DefaultResolver) resolveSegment(ctx context.Context,
	req Request, refresh bool) (Segments, error) {

	local := r.LocalInfo.IsSegLocal(req)
	if !local {
		if refresh {
			return nil, nil
		}
		fetch, err := r.needsFetching(ctx, req)
		if err != nil || fetch {
			return nil, err
		}
	}
	// The segment is local or cached
	res, err := r.loadSegment(ctx, req)
	if err != nil {
		return nil, err
	}
	allRev, err := r.allRevoked(ctx, res)
	if err != nil {
		return nil, err
	}
	// because of revocations our cache is empty, so refetch
	if allRev && !local {
		return nil, nil
	}
	return res.SegMetas(), err
}

func (r *DefaultResolver) loadSegment(ctx context.Context, req Request) (query.Results, error) {
	start, end := req.Src, req.Dst
	consDir := (req.SegType == seg.TypeDown)
	if !consDir {
		start, end = end, start
	}
	return r.DB.Get(ctx, &query.Params{
		StartsAt: []addr.IA{start},
		EndsAt:   []addr.IA{end},
		SegTypes: []seg.Type{req.SegType},
	})
}

func (r *DefaultResolver) needsFetching(ctx context.Context, req Request) (bool, error) {
	nq, err := r.DB.GetNextQuery(ctx, req.Src, req.Dst, nil)
	return time.Now().After(nq), err
}

func (r *DefaultResolver) allRevoked(ctx context.Context, results query.Results) (bool, error) {
	segs := results.Segs()
	filtered, err := segs.FilterSegs(func(ps *seg.PathSegment) (bool, error) {
		return revcache.NoRevokedHopIntf(ctx, r.RevCache, ps)
	})
	if err != nil {
		return false, err
	}
	return len(segs) == 0 && filtered > 0, nil
}
