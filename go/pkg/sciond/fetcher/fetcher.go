// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Package fetcher implements path segment fetching, verification and
// combination logic for SCIOND.
package fetcher

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/sciond/config"
	"github.com/scionproto/scion/go/pkg/trust"
)

const (
	DefaultMinWorkerLifetime = 10 * time.Second
)

type TrustStore interface {
	trust.Inspector
}

type Fetcher interface {
	GetPaths(ctx context.Context, src, dst addr.IA, refresh bool) ([]snet.Path, error)
}

type fetcher struct {
	pather segfetcher.Pather
	config config.SDConfig
}

type FetcherConfig struct {
	RPC       segfetcher.RPC
	PathDB    pathdb.PathDB
	Inspector trust.Inspector

	Verifier infra.Verifier
	RevCache revcache.RevCache
	Cfg      config.SDConfig

	TopoProvider topology.Provider
}

func NewFetcher(cfg FetcherConfig) Fetcher {
	return &fetcher{
		pather: segfetcher.Pather{
			RevCache:     cfg.RevCache,
			TopoProvider: cfg.TopoProvider,
			Fetcher: &segfetcher.Fetcher{
				QueryInterval: cfg.Cfg.QueryInterval.Duration,
				PathDB:        cfg.PathDB,
				Resolver: segfetcher.NewResolver(
					cfg.PathDB,
					cfg.RevCache,
					neverLocal{},
				),
				ReplyHandler: &seghandler.Handler{
					Verifier: &seghandler.DefaultVerifier{Verifier: cfg.Verifier},
					Storage: &seghandler.DefaultStorage{
						PathDB:   cfg.PathDB,
						RevCache: cfg.RevCache,
					},
				},
				Requester: &segfetcher.DefaultRequester{
					RPC:         cfg.RPC,
					DstProvider: &dstProvider{},
				},
				Metrics: segfetcher.NewFetcherMetrics("sd"),
			},
			Splitter: &segfetcher.MultiSegmentSplitter{
				LocalIA:   cfg.TopoProvider.Get().IA(),
				Core:      cfg.TopoProvider.Get().Core(),
				Inspector: cfg.Inspector,
			},
		},
		config: cfg.Cfg,
	}
}

// GetPaths uses the pather to get paths from src to dst.
// src may be either zero or the local IA (nothing else).
func (f *fetcher) GetPaths(ctx context.Context, src, dst addr.IA,
	refresh bool) ([]snet.Path, error) {

	// Check context
	if _, ok := ctx.Deadline(); !ok {
		return nil, serrors.New("context must have deadline set")
	}
	local := f.pather.TopoProvider.Get().IA()
	// Check source
	if !src.IsZero() && !src.Equal(local) {
		return nil, serrors.New("bad source AS", "src", src)
	}
	return f.pather.GetPaths(ctx, dst, refresh)
}

type dstProvider struct {
}

func (r *dstProvider) Dst(_ context.Context, _ segfetcher.Request) (net.Addr, error) {
	return addr.SvcCS, nil
}

type neverLocal struct{}

func (neverLocal) IsSegLocal(_ segfetcher.Request) bool {
	return false
}
