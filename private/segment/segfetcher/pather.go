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
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	rawpath "github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/path/combinator"
	"github.com/scionproto/scion/private/revcache"
)

// Pather errors.
var (
	ErrBadDst = errors.New("bad destination AS")
)

// Pather is used to construct paths from the path database. If necessary, paths
// are fetched over the network.
type Pather struct {
	IA         addr.IA
	MTU        uint16
	NextHopper interface {
		UnderlayNextHop(uint16) *net.UDPAddr
	}
	RevCache revcache.RevCache
	Fetcher  *Fetcher
	Splitter Splitter
}

// GetPaths returns all non-revoked and non-expired paths to the destination.
// The paths are sorted from best to worst according to the weighting in path
// combinator. In case the destination AS is the same as the local AS, a slice
// containing an empty path is returned.
func (p *Pather) GetPaths(ctx context.Context, dst addr.IA,
	refresh bool) ([]snet.Path, error) {

	logger := log.FromCtx(ctx)
	if dst.ISD() == 0 {
		return nil, serrors.WithCtx(ErrBadDst, "dst", dst)
	}
	src := p.IA
	if dst.Equal(src) {
		// For AS local communication, an empty path is used.
		return []snet.Path{path.Path{
			Src: src,
			Dst: dst,
			Meta: snet.PathMetadata{
				MTU:    p.MTU,
				Expiry: time.Now().Add(rawpath.MaxTTL * time.Second),
			},
		}}, nil
	}
	reqs, err := p.Splitter.Split(ctx, dst)
	if err != nil {
		return nil, err
	}
	segs, fetchErr := p.Fetcher.Fetch(ctx, reqs, refresh)
	// Even if fetching failed, attempt to create paths.
	if fetchErr != nil {
		logger.Debug("Fetching failed, attempting to build paths anyway", "err", fetchErr)
	}
	paths := p.buildAllPaths(src, dst, segs)
	paths = p.filterRevoked(ctx, paths)
	if len(paths) == 0 {
		if fetchErr != nil {
			return nil, fetchErr
		}
		return nil, nil
	}
	return p.translatePaths(paths)
}

func (p *Pather) buildAllPaths(src, dst addr.IA, segs Segments) []combinator.Path {
	up, core, down := categorizeSegs(segs)
	destinations := p.findDestinations(dst, up, core)
	var paths []combinator.Path
	for dst := range destinations {
		paths = append(paths, combinator.Combine(src, dst, up, core, down, false)...)
	}
	// Filter expired paths
	now := time.Now()
	var validPaths []combinator.Path
	for _, path := range paths {
		if path.Metadata.Expiry.After(now) {
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
	if dst.ISD() == p.IA.ISD() {
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
	paths []combinator.Path) []combinator.Path {

	logger := log.FromCtx(ctx)
	var newPaths []combinator.Path
	revokedInterfaces := make(map[snet.PathInterface]struct{})
	for _, path := range paths {
		revoked := false
		for _, iface := range path.Metadata.Interfaces {
			// cache automatically expires outdated revocations every second,
			// so a cache hit implies revocation is still active.
			revs, err := p.RevCache.Get(ctx, revcache.SingleKey(iface.IA, iface.ID))
			if err != nil {
				logger.Error("Failed to get revocation", "err", err)
				// continue, the client might still get some usable paths like this.
			}
			if len(revs) > 0 {
				revokedInterfaces[snet.PathInterface{IA: iface.IA, ID: iface.ID}] = struct{}{}
			}
			revoked = revoked || len(revs) > 0
		}
		if !revoked {
			newPaths = append(newPaths, path)
		}
	}
	if len(paths) != len(newPaths) {
		logger.Debug("Filtered paths with revocations",
			"num_paths", len(paths), "num_revoked_paths", len(paths)-len(newPaths),
			"revoked_due_to", revocationsString(revokedInterfaces))
	}
	return newPaths
}

// revocationsString pretty-prints the revocations map to a string.
func revocationsString(revocations map[snet.PathInterface]struct{}) string {
	r := make([]string, 0, len(revocations))
	for i := range revocations {
		r = append(r, i.String())
	}
	sort.Strings(r)
	return fmt.Sprint(r)
}

// translate converts []combinator.Path to []snet.Path.
// Effectively, this adds the NextHop information.
func (p *Pather) translatePaths(cPaths []combinator.Path) ([]snet.Path, error) {
	var paths []snet.Path
	var errs serrors.List
	for _, comb := range cPaths {
		sp, err := p.translatePath(comb)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		paths = append(paths, sp)
	}
	if len(paths) == 0 {
		return nil, serrors.New("no paths after translation", "errs", errs.ToError())
	}
	return paths, nil
}

// translate converts a combinator.Path to an snet.Path.
// Effectively, this adds the NextHop information.
func (p *Pather) translatePath(comb combinator.Path) (snet.Path, error) {
	nextHop := p.NextHopper.UnderlayNextHop(uint16(comb.Metadata.Interfaces[0].ID))
	if nextHop == nil {
		return nil, serrors.New("Unable to find first-hop BR for path",
			"ifid", comb.Metadata.Interfaces[0].ID)
	}
	return path.Path{
		Src:           comb.Metadata.Interfaces[0].IA,
		Dst:           comb.Metadata.Interfaces[len(comb.Metadata.Interfaces)-1].IA,
		DataplanePath: comb.SCIONPath,
		NextHop:       nextHop,
		Meta:          comb.Metadata,
	}, nil
}

// categorizeSegs splits a flat list of segments with type info into one
// separate list per segment type.
func categorizeSegs(segs Segments) (up, core, down seg.Segments) {
	for _, s := range segs {
		switch s.Type {
		case seg.TypeUp:
			up = append(up, s.Segment)
		case seg.TypeCore:
			core = append(core, s.Segment)
		case seg.TypeDown:
			down = append(down, s.Segment)
		}
	}
	return
}
