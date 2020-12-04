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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/pkg/trust"
)

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

	switch {
	case !srcCore && !dstCore:
		if !singleCore.IsZero() {
			return Requests{
				{Src: src, Dst: singleCore, SegType: Up},
				{Src: singleCore, Dst: dst, SegType: Down},
			}, nil
		}
		return Requests{
			{Src: src, Dst: toWildCard(src), SegType: Up},
			{Src: toWildCard(src), Dst: toWildCard(dst), SegType: Core},
			{Src: toWildCard(dst), Dst: dst, SegType: Down},
		}, nil
	case !srcCore && dstCore:
		if (src.I == dst.I && dst.IsWildcard()) || singleCore.Equal(dst) {
			return Requests{{Src: src, Dst: dst, SegType: Up}}, nil
		}
		return Requests{
			{Src: src, Dst: toWildCard(src), SegType: Up},
			{Src: toWildCard(src), Dst: dst, SegType: Core},
		}, nil
	case srcCore && !dstCore:
		if singleCore.Equal(src) {
			return Requests{{Src: src, Dst: dst, SegType: Down}}, nil
		}
		return Requests{
			{Src: src, Dst: toWildCard(dst), SegType: Core},
			{Src: toWildCard(dst), Dst: dst, SegType: Down},
		}, nil
	default:
		return Requests{{Src: src, Dst: dst, SegType: Core}}, nil
	}
}

func (s *MultiSegmentSplitter) inspect(ctx context.Context,
	src, dst addr.IA) (addr.IA, bool, error) {

	if src.I != dst.I {
		isCore, err := s.isCore(ctx, dst)
		return addr.IA{}, isCore, err
	}
	cores, err := s.Inspector.ByAttributes(ctx, src.I, trust.Core)
	if err != nil {
		return addr.IA{}, false, err
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
	return addr.IA{I: ia.I}
}
