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
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/sciond/internal/config"
	"github.com/scionproto/scion/go/sciond/internal/metrics"
)

const (
	DefaultMinWorkerLifetime = 10 * time.Second
)

type TrustStore interface {
	infra.VerificationFactory
	infra.ASInspector
}

type Fetcher interface {
	GetPaths(ctx context.Context, req *sciond.PathReq,
		earlyReplyInterval time.Duration) (*sciond.PathReply, error)
}

type fetcher struct {
	pather segfetcher.Pather
	config config.SDConfig
}

func NewFetcher(requestAPI segfetcher.RequestAPI, pathDB pathdb.PathDB, inspector infra.ASInspector,
	verificationFactory infra.VerificationFactory, revCache revcache.RevCache, cfg config.SDConfig,
	topoProvider topology.Provider) Fetcher {

	localIA := topoProvider.Get().IA()
	return &fetcher{
		pather: segfetcher.Pather{
			PathDB:       pathDB,
			RevCache:     revCache,
			TopoProvider: topoProvider,
			Fetcher: segfetcher.FetcherConfig{
				QueryInterval:       cfg.QueryInterval.Duration,
				LocalIA:             localIA,
				VerificationFactory: verificationFactory,
				PathDB:              pathDB,
				RevCache:            revCache,
				RequestAPI:          requestAPI,
				DstProvider:         &dstProvider{IA: localIA},
				Splitter: &segfetcher.MultiSegmentSplitter{
					Local:     localIA,
					Inspector: inspector,
				},
				SciondMode:       true,
				MetricsNamespace: metrics.Namespace,
				LocalInfo:        neverLocal{},
			}.New(),
		},
		config: cfg,
	}
}

// GetPaths fulfills the path request described by req. GetPaths will attempt
// to build paths at start, after earlyReplyInterval and at context expiration
// (or whenever all background workers return). An earlyReplyInterval of 0
// means no early reply attempt is made.
func (f *fetcher) GetPaths(ctx context.Context, req *sciond.PathReq,
	earlyReplyInterval time.Duration) (*sciond.PathReply, error) {

	// TODO(lukedirtwalker): move to validator, but we need to keep sciond
	// error codes.
	req = req.Copy()
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
		if req.Flags.PathCount != 0 && len(paths) == int(req.Flags.PathCount) {
			break
		}
	}
	if len(errs) > 0 {
		log.FromCtx(ctx).Warn("Errors while translating paths", "errs", errs.ToError())
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
		},
		HostInfo: hostinfo.FromUDPAddr(*nextHop),
	}
	return entry, nil
}

type dstProvider struct {
	IA addr.IA
}

func (r *dstProvider) Dst(_ context.Context, _ segfetcher.Request) (net.Addr, error) {
	return &snet.SVCAddr{IA: r.IA, SVC: addr.SvcPS}, nil
}

type neverLocal struct{}

func (neverLocal) IsSegLocal(_ context.Context, _, _ addr.IA) (bool, error) { return false, nil }
