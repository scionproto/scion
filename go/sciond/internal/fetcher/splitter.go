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

package fetcher

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
)

// NewRequestSplitter creates a request splitter for the given local IA. The AS
// inspector is used to check whether an IA is core or not.
func NewRequestSplitter(localIA addr.IA, inspector infra.ASInspector) segfetcher.Splitter {
	return &sciondRequestSplitter{
		LocalIA:     localIA,
		ASInspector: inspector,
	}
}

// sciondRequestSplitter implements a request splitter for sciond.
type sciondRequestSplitter struct {
	LocalIA     addr.IA
	ASInspector infra.ASInspector
}

func (s *sciondRequestSplitter) Split(ctx context.Context,
	r segfetcher.Request) (segfetcher.RequestSet, error) {

	r.Src = s.srcOrLocalIA(r.Src)
	srcCore, err := s.isCore(ctx, r.Src)
	if err != nil {
		return segfetcher.RequestSet{}, err
	}
	dstCore, err := s.isCore(ctx, r.Dst)
	if err != nil {
		return segfetcher.RequestSet{}, err
	}
	switch {
	case !srcCore && !dstCore:
		return segfetcher.RequestSet{
			Up:    segfetcher.Request{Src: r.Src, Dst: s.toWildCard(r.Src)},
			Cores: []segfetcher.Request{{Src: s.toWildCard(r.Src), Dst: s.toWildCard(r.Dst)}},
			Down:  segfetcher.Request{Src: s.toWildCard(r.Dst), Dst: r.Dst},
		}, nil
	case !srcCore && dstCore:
		if s.isISDLocal(r.Dst) && s.isWildCard(r.Dst) {
			return segfetcher.RequestSet{Up: r}, nil
		}
		return segfetcher.RequestSet{
			Up:    segfetcher.Request{Src: r.Src, Dst: s.toWildCard(r.Src)},
			Cores: []segfetcher.Request{{Src: s.toWildCard(r.Src), Dst: r.Dst}},
		}, nil
	case srcCore && !dstCore:
		return segfetcher.RequestSet{
			Cores: []segfetcher.Request{{Src: r.Src, Dst: s.toWildCard(r.Dst)}},
			Down:  segfetcher.Request{Src: s.toWildCard(r.Dst), Dst: r.Dst},
		}, nil
	default:
		return segfetcher.RequestSet{Cores: []segfetcher.Request{r}}, nil
	}
}

func (s *sciondRequestSplitter) isCore(ctx context.Context, dst addr.IA) (bool, error) {
	if s.isWildCard(dst) {
		return true, nil
	}
	args := infra.ASInspectorOpts{
		RequiredAttributes: []infra.Attribute{infra.Core},
	}
	isCore, err := s.ASInspector.HasAttributes(ctx, dst, args)
	if err != nil {
		return false, err
	}
	return isCore, nil
}

func (s *sciondRequestSplitter) isISDLocal(dst addr.IA) bool {
	return s.LocalIA.I == dst.I
}

func (s *sciondRequestSplitter) isWildCard(dst addr.IA) bool {
	return dst.A == 0
}

func (s *sciondRequestSplitter) toWildCard(dst addr.IA) addr.IA {
	return addr.IA{I: dst.I}
}

func (s *sciondRequestSplitter) srcOrLocalIA(src addr.IA) addr.IA {
	if src.IsZero() {
		return s.LocalIA
	}
	return src
}
