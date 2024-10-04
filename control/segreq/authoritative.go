// Copyright 2020 ETH Zurich
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

package segreq

import (
	"context"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/pathdb/query"
	"github.com/scionproto/scion/private/segment/segfetcher"
)

// AuthoritativeLookup handles path segment lookup requests in a core AS. It
// only returns down and core segments starting at this core AS. It should only
// be used in a core AS.
type AuthoritativeLookup struct {
	LocalIA     addr.IA
	CoreChecker CoreChecker
	PathDB      pathdb.DB
}

func (a AuthoritativeLookup) LookupSegments(ctx context.Context, src,
	dst addr.IA) (segfetcher.Segments, error) {

	segType, err := a.classify(ctx, src, dst)
	if err != nil {
		return nil, err
	}

	switch segType {
	case seg.TypeDown:
		return getDownSegments(ctx, a.PathDB, a.LocalIA, dst)
	case seg.TypeCore:
		return getCoreSegments(ctx, a.PathDB, a.LocalIA, dst)
	default:
		panic("unexpected segType")
	}
}

// classify validates the request and determines the segment type for the request
func (a AuthoritativeLookup) classify(ctx context.Context,
	src, dst addr.IA) (seg.Type, error) {

	switch {
	case src != a.LocalIA:
		return 0, serrors.JoinNoStack(segfetcher.ErrInvalidRequest, nil,
			"src", src, "dst", dst, "reason", "src must be local AS")

	case dst.ISD() == 0:
		return 0, serrors.JoinNoStack(segfetcher.ErrInvalidRequest, nil,
			"src", src, "dst", dst, "reason", "zero ISD dst")

	case dst.ISD() == a.LocalIA.ISD():
		dstCore, err := a.CoreChecker.IsCore(ctx, dst)
		if err != nil {
			return 0, err
		}
		if dstCore {
			return seg.TypeCore, nil
		}
		return seg.TypeDown, nil
	default:
		// We can assume that destination in a remote ISD are core -- otherwise
		// we should not have been asked this and we simply won't find paths.
		return seg.TypeCore, nil
	}
}

// getCoreSegments loads core segments from localIA to dstIA from the path DB.
// Wildcard dstIA is allowed.
func getCoreSegments(ctx context.Context, pathDB pathdb.DB,
	localIA, dstIA addr.IA) (segfetcher.Segments, error) {

	res, err := pathDB.Get(ctx, &query.Params{
		StartsAt: []addr.IA{dstIA},
		EndsAt:   []addr.IA{localIA},
		SegTypes: []seg.Type{seg.TypeCore},
	})
	if err != nil {
		return segfetcher.Segments{}, err
	}
	return res.SegMetas(), nil
}

// getDownSegments loads down segments from localIA to dstIA from the path DB.
// Wildcard dstIA is _not_ allowed.
func getDownSegments(ctx context.Context, pathDB pathdb.DB,
	localIA, dstIA addr.IA) (segfetcher.Segments, error) {

	res, err := pathDB.Get(ctx, &query.Params{
		StartsAt: []addr.IA{localIA},
		EndsAt:   []addr.IA{dstIA},
		SegTypes: []seg.Type{seg.TypeDown},
	})
	if err != nil {
		return segfetcher.Segments{}, err
	}
	return res.SegMetas(), nil
}
