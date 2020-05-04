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
	"net"

	"github.com/scionproto/scion/go/cs/handlers"
	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/cs/segutil"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

// NewFetcher creates a segment fetcher configured for a control service
func NewFetcher(args handlers.HandlerArgs) *segfetcher.Fetcher {
	fetcher := segfetcher.FetcherConfig{
		QueryInterval:    args.QueryInterval,
		Verifier:         args.Verifier,
		PathDB:           args.PathDB,
		RevCache:         args.RevCache,
		RequestAPI:       args.SegRequestAPI,
		LocalInfo:        &localInfo{args.IA},
		MetricsNamespace: metrics.PSNamespace,
		DstProvider:      nil, // see below
	}.New()
	// Recursive/cyclic structure: the dstProvider in the fetcher uses the
	// fetcher (see notes on dstProvider below).
	fetcher.Requester.(*segfetcher.DefaultRequester).DstProvider = &dstProvider{
		localIA: args.IA,
		router: &segutil.Router{
			Pather: segfetcher.Pather{
				PathDB:       args.PathDB,
				RevCache:     args.RevCache,
				TopoProvider: args.TopoProvider,
				Splitter: NewSplitter(
					args.IA,
					args.TopoProvider.Get().Core(),
					args.ASInspector,
					args.PathDB),
				Fetcher: fetcher,
			},
		},
		segSelector: &SegSelector{
			PathDB:       args.PathDB,
			RevCache:     args.RevCache,
			TopoProvider: args.TopoProvider,
		},
	}
	return fetcher
}

type localInfo struct {
	localIA addr.IA
}

// IsSegLocal returns true for segments requests that can be answered authoritatively:
// if this is a non-core AS:
//  - only up segment requests
// if this is a core AS:
//  - down segment requests starting at this AS
//  - core segment requests starting at this AS
// In summary, these are exactly the segments starting at the local AS.
func (l *localInfo) IsSegLocal(ctx context.Context, src, dst addr.IA,
	segType proto.PathSegType) (bool, error) {

	return src == l.localIA, nil
}

// dstProvider provides the address of and the path to the authoritative server
// for a request in the segfetcher.Fetcher (or more specifically, Requester).
// The authoritative server is the core PS at the source of the requested
// segment.
// Certain queries (down segment requests) must be sent to ASes for which the
// path is not a priori locally known. Therefore, this recursively makes use of
// the Fetcher (via Router and Pather) to obtain this path information.
// - Core segment requests are sent only to provider core ASes, so the path
//   will consist of only an up segment.
// - Down segment requests are sent to all core ASes in the destination ISD.
//   The path consists of an up segment and a core segment.
//   The up segment is always locally available, but the core segment might
//   have to be fetched.
// The recursion depth, at runtime, is limited to 2, as this will _only_ be
// called to fetch core segments when requesting down segments.
type dstProvider struct {
	localIA     addr.IA
	router      snet.Router
	segSelector *SegSelector
}

// Dsts provides the address of and the path to the authoritative server for
// this request.
func (p *dstProvider) Dst(ctx context.Context, req segfetcher.Request) (net.Addr, error) {
	if true {
		assert.Must(!p.localIA.Equal(req.Src),
			"segments starting here should have been resolved locally. req: %v", req)
		assert.Must(req.SegType != proto.PathSegType_up,
			"up segments should have been resolved locally. req: %v", req)
		assert.Must(!req.Src.IsWildcard(),
			"wildcard Src must be resolved before forwarding. req: %v", req)
	}

	// The request is directed to the AS at the start of the requested segment:
	dst := req.Src

	var path snet.Path
	var err error
	if req.SegType == proto.PathSegType_core {
		// fast/simple path for core segment requests (only up segment required).
		// Must NOT use the router recursively here;
		// as it tries to find all paths, including paths through other core ASes,
		// the router translates a path lookup to a core to the wildcard segment
		// requests (up localIA->*) and (core *->dst). Looking up the core segment
		// would then lead to an infinite recursion.
		path, err = p.upPath(ctx, dst)
	} else {
		path, err = p.router.Route(ctx, dst)
	}
	if err != nil {
		return nil, err
	}
	addr := &snet.SVCAddr{
		IA:      path.Destination(),
		Path:    path.Path(),
		NextHop: path.UnderlayNextHop(),
		SVC:     addr.SvcPS,
	}
	return addr, nil
}

func (p *dstProvider) upPath(ctx context.Context, dst addr.IA) (snet.Path, error) {
	return p.segSelector.SelectSeg(ctx, &query.Params{
		StartsAt: []addr.IA{dst},
		EndsAt:   []addr.IA{p.localIA},
		SegTypes: []proto.PathSegType{proto.PathSegType_up},
	})
}
