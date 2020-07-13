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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/proto"
)

// NewAuthoritativeHandler creates a segment request handler that returns down
// and core segments starting at this core AS.
// This handler is used exclusively in core ASes.
func NewAuthoritativeHandler(ia addr.IA, inspector trust.Inspector, pathDB pathdb.PathDB,
	revCache revcache.RevCache) infra.Handler {

	return &baseHandler{
		processor: &authoritativeProcessor{
			localIA:     ia,
			coreChecker: CoreChecker{inspector},
			pathDB:      pathDB,
		},
		revCache: revCache,
	}
}

// authoritativeProcesser handles segment requests for down and core segents
// starting at this core AS.
type authoritativeProcessor struct {
	localIA     addr.IA
	coreChecker CoreChecker
	pathDB      pathdb.PathDB
}

func (h *authoritativeProcessor) process(ctx context.Context,
	req *path_mgmt.SegReq) (segfetcher.Segments, error) {

	src := req.SrcIA()
	dst := req.DstIA()
	segType, err := h.classify(ctx, src, dst)
	if err != nil {
		return nil, err
	}

	switch segType {
	case proto.PathSegType_down:
		return getDownSegments(ctx, h.pathDB, h.localIA, dst)
	case proto.PathSegType_core:
		return getCoreSegments(ctx, h.pathDB, h.localIA, dst)
	default:
		panic("unexpected segType")
	}
}

// classify validates the request and determines the segment type for the request
func (h *authoritativeProcessor) classify(ctx context.Context,
	src, dst addr.IA) (proto.PathSegType, error) {

	switch {
	case src != h.localIA:
		return proto.PathSegType_unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
			"src", src, "dst", dst, "reason", "src must be local AS")
	case dst.I == 0:
		return proto.PathSegType_unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
			"src", src, "dst", dst, "reason", "zero ISD dst")
	case dst.I == h.localIA.I:
		dstCore, err := h.coreChecker.IsCore(ctx, dst)
		if err != nil {
			return proto.PathSegType_unset, err
		}
		if dstCore {
			return proto.PathSegType_core, nil
		}
		return proto.PathSegType_down, nil
	default:
		// We can assume that destination in a remote ISD are core -- otherwise
		// we should not have been asked this and we simply won't find paths.
		return proto.PathSegType_core, nil
	}
}

// getCoreSegments loads core segments from localIA to dstIA from the path DB.
// Wildcard dstIA is allowed.
func getCoreSegments(ctx context.Context, pathDB pathdb.PathDB,
	localIA, dstIA addr.IA) (segfetcher.Segments, error) {

	res, err := pathDB.Get(ctx, &query.Params{
		StartsAt: []addr.IA{dstIA},
		EndsAt:   []addr.IA{localIA},
		SegTypes: []proto.PathSegType{proto.PathSegType_core},
	})
	if err != nil {
		return segfetcher.Segments{}, err
	}
	return res.SegMetas(), nil
}

// getDownSegments loads down segments from localIA to dstIA from the path DB.
// Wildcard dstIA is _not_ allowed.
func getDownSegments(ctx context.Context, pathDB pathdb.PathDB,
	localIA, dstIA addr.IA) (segfetcher.Segments, error) {

	res, err := pathDB.Get(ctx, &query.Params{
		StartsAt: []addr.IA{localIA},
		EndsAt:   []addr.IA{dstIA},
		SegTypes: []proto.PathSegType{proto.PathSegType_down},
	})
	if err != nil {
		return segfetcher.Segments{}, err
	}
	return res.SegMetas(), nil
}
