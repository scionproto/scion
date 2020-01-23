// Copyright 2020 Anapaya Systems
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

package segfetcher

import (
	"context"
	"errors"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
)

// Pather errors.
var (
	ErrBadDst  = errors.New("bad destination AS")
	ErrNoPaths = errors.New("no paths found")
)

// Pather is used to construct paths from the path database. If necessary, paths
// are fetched over the network.
type Pather struct {
	PathDB       pathdb.PathDB
	RevCache     revcache.RevCache
	TopoProvider topology.Provider
	Fetcher      *Fetcher
}

// GetPaths returns all non-revoked and non-expired paths to the destination.
// The paths are sorted from best to worst according to the weighting in path
// combinator. In case the destination AS is the same as the local AS, a slice
// containing an empty path is returned.
func (p *Pather) GetPaths(ctx context.Context, dst addr.IA,
	refresh bool) ([]*combinator.Path, error) {

	if dst.I == 0 {
		return nil, serrors.WithCtx(ErrBadDst, "dst", dst)
	}
	src := p.TopoProvider.Get().IA()
	if dst.Equal(src) {
		// For AS local communication, an empty path is used.
		return []*combinator.Path{{}}, nil
	}
	req := Request{Src: src, Dst: dst}
	if refresh {
		req.State = Fetch
	}
	segs, err := p.Fetcher.FetchSegs(ctx, req)
	if err != nil {
		return nil, err
	}
	paths := p.buildAllPaths(src, dst, segs)
	paths, err = p.filterRevoked(ctx, paths)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, ErrNoPaths
	}
	return paths, nil
}

func (p *Pather) buildAllPaths(src, dst addr.IA, segs Segments) []*combinator.Path {
	destinations := p.findDestinations(dst, segs.Up, segs.Core)
	var paths []*combinator.Path
	for dst := range destinations {
		paths = append(paths, combinator.Combine(src, dst, segs.Up, segs.Core, segs.Down)...)
	}
	// Filter expired paths
	now := time.Now()
	var validPaths []*combinator.Path
	for _, path := range paths {
		if path.ComputeExpTime().After(now) {
			validPaths = append(validPaths, path)
		}
	}
	return validPaths
}

func (p *Pather) findDestinations(dst addr.IA, ups, cores seg.Segments) map[addr.IA]struct{} {
	if !dst.IsWildcard() {
		return map[addr.IA]struct{}{dst: {}}
	}
	all := cores.FirstIAs()
	if dst.I == p.TopoProvider.Get().IA().I {
		// for isd local wildcard we want to reach cores, they are at the end of the up segs.
		all = append(all, ups.FirstIAs()...)
	}
	destinations := make(map[addr.IA]struct{})
	for _, dst := range all {
		destinations[dst] = struct{}{}
	}
	return destinations
}

func (p *Pather) filterRevoked(ctx context.Context,
	paths []*combinator.Path) ([]*combinator.Path, error) {

	logger := log.FromCtx(ctx)
	var newPaths []*combinator.Path
	for _, path := range paths {
		revoked := false
		for _, iface := range path.Interfaces {
			// cache automatically expires outdated revocations every second,
			// so a cache hit implies revocation is still active.
			revs, err := p.RevCache.Get(ctx, revcache.SingleKey(iface.IA(), iface.IfID))
			if err != nil {
				logger.Error("[segutil.Pather] Failed to get revocation", "err", err)
				// continue, the client might still get some usable paths like this.
			}
			revoked = revoked || len(revs) > 0
		}
		if !revoked {
			newPaths = append(newPaths, path)
		}
	}
	if len(paths) != len(newPaths) {
		logger.Trace("[segutil.Pather] Filtered paths with revocations",
			"all", paths, "revoked", len(paths)-len(newPaths))
	}
	return newPaths, nil
}
