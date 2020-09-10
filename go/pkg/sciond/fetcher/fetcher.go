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
	"bytes"
	"context"
	"errors"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/hostinfo"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
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
	GetPaths(ctx context.Context, req *sciond.PathReq) (*sciond.PathReply, error)
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
	HeaderV2     bool
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
					DstProvider: &dstProvider{TopologyProvider: cfg.TopoProvider},
				},
				Metrics: segfetcher.NewFetcherMetrics("sd"),
			},
			Splitter: &segfetcher.MultiSegmentSplitter{
				LocalIA:   cfg.TopoProvider.Get().IA(),
				Core:      cfg.TopoProvider.Get().Core(),
				Inspector: cfg.Inspector,
			},
			HeaderV2: cfg.HeaderV2,
		},
		config: cfg.Cfg,
	}
}

// GetPaths fulfills the path request described by req.
func (f *fetcher) GetPaths(ctx context.Context, req *sciond.PathReq) (*sciond.PathReply, error) {
	// Check context
	if _, ok := ctx.Deadline(); !ok {
		return nil, serrors.New("Context must have deadline set")
	}
	local := f.pather.TopoProvider.Get().IA()
	// Check source
	if !req.Src.IA().IsZero() && !req.Src.IA().Equal(local) {
		return &sciond.PathReply{ErrorCode: sciond.ErrorBadSrcIA},
			serrors.New("Bad source AS", "src", req.Src.IA())
	}
	cPaths, err := f.pather.GetPaths(ctx, req.Dst.IA(), req.Flags.Refresh)
	switch {
	case err == nil:
		break
	case errors.Is(err, segfetcher.ErrBadDst):
		return &sciond.PathReply{ErrorCode: sciond.ErrorBadDstIA}, err
	case errors.Is(err, segfetcher.ErrNoPaths):
		return &sciond.PathReply{ErrorCode: sciond.ErrorNoPaths}, err
	default:
		return &sciond.PathReply{ErrorCode: sciond.ErrorInternal}, err
	}
	var paths []sciond.PathReplyEntry
	var errs serrors.List
	for _, path := range cPaths {
		p, err := f.translate(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		paths = append(paths, p)
	}
	if len(errs) > 0 {
		log.FromCtx(ctx).Info("Errors while translating paths", "errs", errs.ToError())
	}
	if len(paths) == 0 {
		return nil, serrors.New("no paths after translation", "errs", errs.ToError())
	}
	return &sciond.PathReply{ErrorCode: sciond.ErrorOk, Entries: paths}, nil
}

// translate returns a translated sciond.PathReplyEntry objects from the
// combinator path.
//
// For an empty path, the resulting entry contains an empty RawFwdPath, the MTU
// is set to the MTU of the local AS and an expiration time of time.Now() +
// MAX_SEGMENT_TTL.
func (f *fetcher) translate(path *combinator.Path) (sciond.PathReplyEntry, error) {
	if len(path.Segments) == 0 {
		entry := sciond.PathReplyEntry{
			Path: &sciond.FwdPathMeta{
				FwdPath:    []byte{},
				Mtu:        f.pather.TopoProvider.Get().MTU(),
				Interfaces: []sciond.PathInterface{},
				ExpTime:    util.TimeToSecs(time.Now().Add(spath.MaxTTL * time.Second)),
				HeaderV2:   path.HeaderV2,
			},
		}
		return entry, nil
	}
	x := &bytes.Buffer{}
	_, err := path.WriteTo(x)
	if err != nil {
		// In-memory write should never fail
		panic(err)
	}
	nextHop, ok := f.pather.TopoProvider.Get().UnderlayNextHop(path.Interfaces[0].IfID)
	if !ok {
		return sciond.PathReplyEntry{}, serrors.New("unable to find first-hop BR for path",
			"ifid", path.Interfaces[0].IfID)
	}
	entry := sciond.PathReplyEntry{
		Path: &sciond.FwdPathMeta{
			FwdPath:    x.Bytes(),
			Mtu:        path.Mtu,
			Interfaces: path.Interfaces,
			ExpTime:    uint32(path.ComputeExpTime().Unix()),
			Metadata:   CondenseMetadata(path.Metadata),
			HeaderV2:   path.HeaderV2,
		},
		HostInfo: hostinfo.FromUDPAddr(*nextHop),
	}
	return entry, nil
}

type dstProvider struct {
	TopologyProvider topology.Provider
}

func (r *dstProvider) Dst(_ context.Context, _ segfetcher.Request) (net.Addr, error) {
	return r.TopologyProvider.Get().Anycast(addr.SvcCS)
}

type neverLocal struct{}

func (neverLocal) IsSegLocal(_ segfetcher.Request) bool {
	return false
}
