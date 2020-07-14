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
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/proto"
)

type wildcardExpander struct {
	localIA   addr.IA
	core      bool
	inspector trust.Inspector
	pathDB    pathdb.PathDB
}

func (e *wildcardExpander) ExpandSrcWildcard(ctx context.Context,
	req segfetcher.Request) (segfetcher.Requests, error) {

	if req.Src.A != 0 {
		return segfetcher.Requests{req}, nil
	}

	switch req.SegType {
	case proto.PathSegType_core:
		cores, err := e.providerCoreASes(ctx)
		if err != nil {
			return nil, err
		}
		return requestsSrcsToDst(cores, req.Dst, req.SegType), nil
	case proto.PathSegType_down:
		cores, err := e.coreASes(ctx, req.Src.I)
		if err != nil {
			return nil, err
		}
		return requestsSrcsToDst(cores, req.Dst, req.SegType), nil
	default:
		// no wildcard source for up requests
		panic("Unexpected wildcard for up segment request, should not have passed validation")
	}
}

// coreASes queries the core ASes in isd.
func (e *wildcardExpander) coreASes(ctx context.Context, isd addr.ISD) ([]addr.IA, error) {
	coreASes, err := e.inspector.ByAttributes(ctx, isd, trust.Core)
	if err != nil {
		return nil, serrors.WrapStr("failed to get local core ASes", err)
	}
	return coreASes, nil
}

// providerCoreASes returns the core ASes that are providers of this AS, i.e.
// those core ASes that are directly reachable with an up segment
func (e *wildcardExpander) providerCoreASes(ctx context.Context) ([]addr.IA, error) {

	if e.core {
		return []addr.IA{e.localIA}, nil
	}

	params := &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_up},
	}
	res, err := e.pathDB.Get(ctx, params)
	if err != nil {
		return nil, err
	}
	segs := query.Results(res).Segs()
	return segs.FirstIAs(), nil
}

// requestsSrcsToDst creates a slice containing a request for each src in srcs to dst
func requestsSrcsToDst(srcs []addr.IA, dst addr.IA, segType proto.PathSegType) segfetcher.Requests {
	requests := make(segfetcher.Requests, 0, len(srcs))
	for _, src := range srcs {
		if src != dst {
			requests = append(requests, segfetcher.Request{Src: src, Dst: dst, SegType: segType})
		}
	}
	return requests
}
