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
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/proto"
)

// NewForwardingHandler creates a forwarding segment request handler.
// This handler is used (exclusively) for AS-local segment requests.
func NewForwardingHandler(ia addr.IA, core bool, inspector trust.Inspector,
	pathDB pathdb.PathDB, revCache revcache.RevCache, fetcher *segfetcher.Fetcher) infra.Handler {

	return &baseHandler{
		processor: &forwarder{
			localIA:     ia,
			coreChecker: CoreChecker{inspector},
			fetcher:     fetcher,
			expander: &wildcardExpander{
				localIA:   ia,
				core:      core,
				inspector: inspector,
				pathDB:    pathDB,
			},
		},
		revCache: revCache,
	}
}

// forwarder is the processor for segment requests for AS-local segment requests.
// - requests for up segment are answered directly, from the local DB
// - down and core segments are forwarded to the responsible core ASes, and results are cached
type forwarder struct {
	localIA     addr.IA
	coreChecker CoreChecker
	fetcher     *segfetcher.Fetcher
	expander    *wildcardExpander
}

func (h *forwarder) process(ctx context.Context,
	req *path_mgmt.SegReq) (segfetcher.Segments, error) {

	src := req.SrcIA()
	dst := req.DstIA()
	segType, err := h.classify(ctx, src, dst)
	if err != nil {
		return segfetcher.Segments{}, err
	}

	reqs, err := h.expander.ExpandSrcWildcard(ctx,
		segfetcher.Request{Src: src, Dst: dst, SegType: segType})
	if err != nil {
		return segfetcher.Segments{},
			serrors.WrapStr("failed to expand core wildcard request", err)
	}

	return h.fetcher.Fetch(ctx, reqs, false)
}

// classify validates the request and determines the segment type for the request
func (h *forwarder) classify(ctx context.Context, src, dst addr.IA) (proto.PathSegType, error) {
	unset := proto.PathSegType_unset // shorthand
	if src.I == 0 || dst.I == 0 {
		return unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
			"src", src, "dst", dst, "reason", "zero ISD src or dst")
	}
	if dst == h.localIA {
		// this could be an otherwise valid request, but probably the requester switched Src and Dst
		return unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
			"src", src, "dst", dst, "reason", "dst is local AS, confusion?")
	}
	srcCore, err := h.coreChecker.IsCore(ctx, src)
	if err != nil {
		return proto.PathSegType_unset, err
	}
	dstCore, err := h.coreChecker.IsCore(ctx, dst)
	if err != nil {
		return proto.PathSegType_unset, err
	}
	switch {
	case srcCore && dstCore:
		// core
		if src.I != h.localIA.I {
			return unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
				"src", src, "dst", dst, "reason", "core segment request src ISD not local ISD")
		}
		return proto.PathSegType_core, nil
	case srcCore:
		// down
		if src.I != dst.I {
			return unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
				"src", src, "dst", dst, "reason", "down segment request src/dst in different ISD")
		}
		return proto.PathSegType_down, nil
	case dstCore:
		// up
		if src != h.localIA {
			return unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
				"src", src, "dst", dst, "reason", "up segment request src not local AS")
		}
		if dst.I != h.localIA.I {
			return unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
				"src", src, "dst", dst, "reason", "up segment request dst in different ISD")
		}
		return proto.PathSegType_up, nil
	default:
		return unset, serrors.WithCtx(segfetcher.ErrInvalidRequest,
			"src", src, "dst", dst, "reason", "non-core src & dst")
	}
}
