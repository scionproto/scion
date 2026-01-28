// Copyright 2019 Anapaya Systems
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

	"github.com/scionproto/scion/pkg/addr"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/trust"
)

// ctxKey is used for context keys in this package.
type ctxKey string

// SkipOneHopKey is a context key that, when set, instructs the splitter to skip
// creating one-hop segment requests. This is used to avoid infinite recursion
// when the dstProvider needs to find a path to a remote core AS for forwarding
// a one-hop segment request.
const SkipOneHopKey ctxKey = "skipOneHop"

// SkipOneHop returns true if one-hop segment requests should be skipped.
func SkipOneHop(ctx context.Context) bool {
	return ctx.Value(SkipOneHopKey) != nil
}

// Splitter splits a path request into set of segment requests.
type Splitter interface {
	// Split splits a path request from the local AS to dst into a set of segment requests.
	Split(ctx context.Context, dst addr.IA) (Requests, error)
}

// MultiSegmentSplitter splits requests consisting of one or multiple segments.
// The AS inspector is used to check whether an IA is core or not.
type MultiSegmentSplitter struct {
	LocalIA   addr.IA
	Core      bool
	Inspector trust.Inspector
}

// Split splits a path request from the local AS to dst into a set of segment requests.
func (s *MultiSegmentSplitter) Split(ctx context.Context, dst addr.IA) (Requests, error) {

	const Up = seg.TypeUp
	const Down = seg.TypeDown
	const Core = seg.TypeCore

	src := s.LocalIA
	srcCore := s.Core
	singleCore, dstCore, err := s.inspect(ctx, src, dst)
	if err != nil {
		return nil, err
	}

	// Check if we should skip one-hop segment requests (to avoid recursion in dstProvider)
	skipOneHop := SkipOneHop(ctx)

	switch {
	case !srcCore && !dstCore:
		if !singleCore.IsZero() {
			return Requests{
				{Src: src, Dst: singleCore, SegType: Up},
				{Src: singleCore, Dst: dst, SegType: Down},
			}, nil
		}
		srcWildcard := toWildCard(src)
		dstWildcard := toWildCard(dst)
		reqs := Requests{
			{Src: src, Dst: srcWildcard, SegType: Up},
			{Src: srcWildcard, Dst: dstWildcard, SegType: Core},
			{Src: dstWildcard, Dst: dst, SegType: Down},
		}
		// Add one-hop segment requests for peering path discovery (skip if in recursive lookup)
		if !skipOneHop {
			srcCores, _ := s.Inspector.ByAttributes(ctx, src.ISD(), trust.Core)
			for _, c := range srcCores {
				reqs = append(reqs, Request{Src: c, Dst: c, SegType: Up})
			}
			if src.ISD() != dst.ISD() {
				dstCores, _ := s.Inspector.ByAttributes(ctx, dst.ISD(), trust.Core)
				for _, c := range dstCores {
					reqs = append(reqs, Request{Src: c, Dst: c, SegType: Down})
				}
			}
		}
		return reqs, nil
	case !srcCore && dstCore:
		if (src.ISD() == dst.ISD() && dst.IsWildcard()) || singleCore.Equal(dst) {
			return Requests{{Src: src, Dst: dst, SegType: Up}}, nil
		}
		srcWildcard := toWildCard(src)
		reqs := Requests{
			{Src: src, Dst: srcWildcard, SegType: Up},
			{Src: srcWildcard, Dst: dst, SegType: Core},
		}
		// Add one-hop segment requests for peering path discovery (skip if in recursive lookup)
		if !skipOneHop {
			reqs = append(reqs, Request{Src: dst, Dst: dst, SegType: Down})
			srcCores, _ := s.Inspector.ByAttributes(ctx, src.ISD(), trust.Core)
			for _, c := range srcCores {
				reqs = append(reqs, Request{Src: c, Dst: c, SegType: Up})
			}
		}
		return reqs, nil
	case srcCore && !dstCore:
		if singleCore.Equal(src) {
			return Requests{{Src: src, Dst: dst, SegType: Down}}, nil
		}
		dstWildcard := toWildCard(dst)
		reqs := Requests{
			{Src: src, Dst: dstWildcard, SegType: Core},
			{Src: dstWildcard, Dst: dst, SegType: Down},
		}
		// Add one-hop segment requests for peering path discovery (skip if in recursive lookup)
		if !skipOneHop {
			reqs = append(reqs, Request{Src: src, Dst: src, SegType: Up})
			dstCores, _ := s.Inspector.ByAttributes(ctx, dst.ISD(), trust.Core)
			for _, c := range dstCores {
				reqs = append(reqs, Request{Src: c, Dst: c, SegType: Down})
			}
		}
		return reqs, nil
	default:
		reqs := Requests{
			{Src: src, Dst: dst, SegType: Core},
		}
		// Add one-hop segment requests for peering path discovery (skip if in recursive lookup)
		if !skipOneHop {
			reqs = append(reqs, Request{Src: src, Dst: src, SegType: Up})
			reqs = append(reqs, Request{Src: dst, Dst: dst, SegType: Down})
		}
		return reqs, nil
	}
}

func (s *MultiSegmentSplitter) inspect(ctx context.Context,
	src, dst addr.IA) (addr.IA, bool, error) {

	if src.ISD() != dst.ISD() {
		isCore, err := s.isCore(ctx, dst)
		return 0, isCore, err
	}
	cores, err := s.Inspector.ByAttributes(ctx, src.ISD(), trust.Core)
	if err != nil {
		return 0, false, err
	}
	var single addr.IA
	if len(cores) == 1 {
		single = cores[0]
	}
	for _, c := range cores {
		if c.Equal(dst) {
			return single, true, nil
		}
	}
	return single, dst.IsWildcard(), nil
}

func (s *MultiSegmentSplitter) isCore(ctx context.Context, dst addr.IA) (bool, error) {
	if dst.IsWildcard() {
		return true, nil
	}
	isCore, err := s.Inspector.HasAttributes(ctx, dst, trust.Core)
	if err != nil {
		return false, err
	}
	return isCore, nil
}

func toWildCard(ia addr.IA) addr.IA {
	return addr.MustIAFrom(ia.ISD(), 0)
}
