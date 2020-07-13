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
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/cs/segutil"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/proto"
)

type FetcherConfig struct {
	IA           addr.IA
	TopoProvider topology.Provider
	Inspector    trust.Inspector

	// QueryInterval specifies after how much time segments should be
	// refetched at the remote server.
	QueryInterval time.Duration
	// Verifier is the verifier to use.
	Verifier infra.Verifier
	// PathDB is the path db to use.
	PathDB pathdb.PathDB
	// RevCache is the revocation cache to use.
	RevCache revcache.RevCache
	// RequestAPI is the request api to use.
	RequestAPI segfetcher.RequestAPI

	HeaderV2 bool
}

// NewFetcher creates a segment fetcher configured for fetching segments from
// inside the control service
func NewFetcher(cfg FetcherConfig) *segfetcher.Fetcher {

	fetcher := segfetcher.FetcherConfig{
		QueryInterval:    cfg.QueryInterval,
		Verifier:         cfg.Verifier,
		PathDB:           cfg.PathDB,
		RevCache:         cfg.RevCache,
		RequestAPI:       cfg.RequestAPI,
		LocalInfo:        &localInfo{cfg.IA},
		MetricsNamespace: metrics.PSNamespace,
		DstProvider:      nil, // see below
	}.New()
	// Recursive/cyclic structure: the dstProvider in the fetcher uses the
	// fetcher (see notes on dstProvider below).
	fetcher.Requester.(*segfetcher.DefaultRequester).DstProvider = &dstProvider{
		localIA: cfg.IA,
		router:  newRouter(cfg, fetcher),
		segSelector: &SegSelector{
			PathDB:       cfg.PathDB,
			RevCache:     cfg.RevCache,
			TopoProvider: cfg.TopoProvider,
			Pather:       addrutil.NewPather(cfg.TopoProvider, cfg.HeaderV2),
		},
	}

	return fetcher
}

// NewRouter creates a new Router/Pather/Fetcher, configured for obtaining paths
// from inside the control service
func NewRouter(cfg FetcherConfig) snet.Router {
	fetcher := NewFetcher(cfg)
	return newRouter(cfg, fetcher)
}

func newRouter(cfg FetcherConfig, fetcher *segfetcher.Fetcher) snet.Router {
	return &segutil.Router{
		Pather: segfetcher.Pather{
			TopoProvider: cfg.TopoProvider,
			RevCache:     cfg.RevCache,
			Splitter: NewSplitter(
				cfg.IA,
				cfg.TopoProvider.Get().Core(),
				cfg.Inspector,
				cfg.PathDB),
			Fetcher: fetcher,
		},
	}
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
func (l *localInfo) IsSegLocal(req segfetcher.Request) bool {
	return req.Src == l.localIA
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

	// The request is directed to the AS at the start of the requested segment:
	dst := req.Src

	var path snet.Path
	var err error
	switch req.SegType {
	case proto.PathSegType_core:
		// fast/simple path for core segment requests (only up segment required).
		// Must NOT use the router recursively here;
		// as it tries to find all paths, including paths through other core ASes,
		// the router translates a path lookup to a core to the wildcard segment
		// requests (up localIA->*) and (core *->dst). Looking up the core segment
		// would then lead to an infinite recursion.
		path, err = p.upPath(ctx, dst)
	case proto.PathSegType_down:
		path, err = p.router.Route(ctx, dst)
	default:
		panic(fmt.Errorf("Unsupported segment type for request forwarding. "+
			"Up segment should have been resolved locally. SegType: %s", req.SegType))
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
