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
	"github.com/scionproto/scion/private/trust"
)

type WildcardExpander struct {
	LocalIA   addr.IA
	Core      bool
	Inspector trust.Inspector
	PathDB    pathdb.DB
}

func (e *WildcardExpander) ExpandSrcWildcard(ctx context.Context,
	req segfetcher.Request) (segfetcher.Requests, error) {

	if req.Src.AS() != 0 {
		return segfetcher.Requests{req}, nil
	}

	switch req.SegType {
	case seg.TypeCore:
		cores, err := e.providerCoreASes(ctx)
		if err != nil {
			return nil, err
		}
		return requestsSrcsToDst(cores, req.Dst, req.SegType), nil
	case seg.TypeDown:
		cores, err := e.coreASes(ctx, req.Src.ISD())
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
func (e *WildcardExpander) coreASes(ctx context.Context, isd addr.ISD) ([]addr.IA, error) {
	coreASes, err := e.Inspector.ByAttributes(ctx, isd, trust.Core)
	if err != nil {
		return nil, serrors.Wrap("failed to get local core ASes", err)
	}
	return coreASes, nil
}

// providerCoreASes returns the core ASes that are providers of this AS, i.e.
// those core ASes that are directly reachable with an up segment
func (e *WildcardExpander) providerCoreASes(ctx context.Context) ([]addr.IA, error) {

	if e.Core {
		return []addr.IA{e.LocalIA}, nil
	}

	params := &query.Params{
		SegTypes: []seg.Type{seg.TypeUp},
	}
	res, err := e.PathDB.Get(ctx, params)
	if err != nil {
		return nil, err
	}
	segs := res.Segs()
	return segs.FirstIAs(), nil
}

// requestsSrcsToDst creates a slice containing a request for each src in srcs to dst
func requestsSrcsToDst(srcs []addr.IA, dst addr.IA, segType seg.Type) segfetcher.Requests {
	requests := make(segfetcher.Requests, 0, len(srcs))
	for _, src := range srcs {
		if src != dst {
			requests = append(requests, segfetcher.Request{Src: src, Dst: dst, SegType: segType})
		}
	}
	return requests
}
