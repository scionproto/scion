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
	"github.com/scionproto/scion/go/lib/infra"
)

// Splitter splits a single request into a request set.
type Splitter interface {
	// Split splits the request into a request set. Assumes that the request
	// has been validated for the local IA.
	Split(ctx context.Context, r Request) (RequestSet, error)
}

// MultiSegmentSplitter splits requests consisting of one or multiple segments.
// The AS inspector is used to check whether an IA is core or not.
type MultiSegmentSplitter struct {
	Local     addr.IA
	Inspector infra.ASInspector
}

// Split splits the request consisting of one or multiple segments.
func (s *MultiSegmentSplitter) Split(ctx context.Context,
	r Request) (RequestSet, error) {

	if r.Src.IsZero() {
		r.Src = s.Local
	}
	srcCore, err := s.isCore(ctx, r.Src)
	if err != nil {
		return RequestSet{}, err
	}
	dstCore, err := s.isCore(ctx, r.Dst)
	if err != nil {
		return RequestSet{}, err
	}
	switch {
	case !srcCore && !dstCore:
		return RequestSet{
			Up:    Request{Src: r.Src, Dst: toWildCard(r.Src)},
			Cores: []Request{{Src: toWildCard(r.Src), Dst: toWildCard(r.Dst)}},
			Down:  Request{Src: toWildCard(r.Dst), Dst: r.Dst},
			Fetch: r.State == Fetch,
		}, nil
	case !srcCore && dstCore:
		if s.isISDLocal(r.Dst) && r.Dst.IsWildcard() {
			return RequestSet{
				Up:    r,
				Fetch: r.State == Fetch,
			}, nil
		}
		return RequestSet{
			Up:    Request{Src: r.Src, Dst: toWildCard(r.Src)},
			Cores: []Request{{Src: toWildCard(r.Src), Dst: r.Dst}},
			Fetch: r.State == Fetch,
		}, nil
	case srcCore && !dstCore:
		return RequestSet{
			Cores: []Request{{Src: r.Src, Dst: toWildCard(r.Dst)}},
			Down:  Request{Src: toWildCard(r.Dst), Dst: r.Dst},
			Fetch: r.State == Fetch,
		}, nil
	default:
		return RequestSet{
			Cores: []Request{r},
			Fetch: r.State == Fetch,
		}, nil
	}
}

func (s *MultiSegmentSplitter) isCore(ctx context.Context, dst addr.IA) (bool, error) {
	if dst.IsWildcard() {
		return true, nil
	}
	args := infra.ASInspectorOpts{
		RequiredAttributes: []infra.Attribute{infra.Core},
	}
	isCore, err := s.Inspector.HasAttributes(ctx, dst, args)
	if err != nil {
		return false, err
	}
	return isCore, nil
}

func (s *MultiSegmentSplitter) isISDLocal(dst addr.IA) bool {
	return s.Local.I == dst.I
}

func toWildCard(ia addr.IA) addr.IA {
	return addr.IA{I: ia.I}
}
