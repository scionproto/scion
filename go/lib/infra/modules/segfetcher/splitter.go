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
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
)

// RequestSplitter splits a single request into a request set.
type RequestSplitter interface {
	// Split splits the request into a request set. Assumes that the request
	// has been validated for the local IA.
	Split(ctx context.Context, r Request) (RequestSet, error)
}

// NewRequestSplitter creates a request splitter for the given local IA. The
// TRC provider is used to get TRCs and check whether an IA is core or not.
func NewRequestSplitter(localIA addr.IA, inspector infra.ASInspector) (
	RequestSplitter, error) {

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	baseSplitter := baseRequestSplitter{
		LocalIA:     localIA,
		ASInspector: inspector,
	}
	core, err := baseSplitter.isCore(ctx, localIA)
	if err != nil {
		return nil, err
	}
	if core {
		return &coreRequestSplitter{
			baseRequestSplitter: baseSplitter,
		}, nil
	}
	return &nonCoreRequestSplitter{
		baseRequestSplitter: baseSplitter,
	}, nil
}

// baseRequestSplitter implements common functionality for request splitters.
type baseRequestSplitter struct {
	LocalIA     addr.IA
	ASInspector infra.ASInspector
}

func (s *baseRequestSplitter) isCore(ctx context.Context, dst addr.IA) (bool, error) {
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

func (s *baseRequestSplitter) isISDLocal(dst addr.IA) bool {
	return s.LocalIA.I == dst.I
}

func (s *baseRequestSplitter) isWildCard(dst addr.IA) bool {
	return dst.A == 0
}

func (s *baseRequestSplitter) toWildCard(dst addr.IA) addr.IA {
	return addr.IA{I: dst.I}
}

func (s *baseRequestSplitter) srcOrLocalIA(src addr.IA) addr.IA {
	if src.IsZero() {
		return s.LocalIA
	}
	return src
}

type coreRequestSplitter struct {
	baseRequestSplitter
}

func (s *coreRequestSplitter) Split(ctx context.Context, r Request) (RequestSet, error) {
	core, err := s.isCore(ctx, r.Dst)
	if err != nil {
		return RequestSet{}, err
	}
	src := s.srcOrLocalIA(r.Src)
	if core {
		// core to core
		return RequestSet{
			Cores: []Request{{Src: src, Dst: r.Dst}},
		}, nil
	}
	return RequestSet{
		Cores: []Request{{Src: src, Dst: s.toWildCard(r.Dst)}},
		Down:  Request{Src: s.toWildCard(r.Dst), Dst: r.Dst},
	}, nil
}

type nonCoreRequestSplitter struct {
	baseRequestSplitter
}

func (s *nonCoreRequestSplitter) Split(ctx context.Context, r Request) (RequestSet, error) {
	core, err := s.isCore(ctx, r.Dst)
	if err != nil {
		return RequestSet{}, err
	}
	wildcard := s.isWildCard(r.Dst)
	local := s.isISDLocal(r.Dst)
	src := s.srcOrLocalIA(r.Src)
	switch {
	case core && wildcard && local:
		return RequestSet{
			Up: Request{Src: src, Dst: r.Dst},
		}, nil
	case core:
		return RequestSet{
			Up:    Request{Src: src, Dst: s.toWildCard(src)},
			Cores: []Request{{Src: s.toWildCard(src), Dst: r.Dst}},
		}, nil
	default:
		return RequestSet{
			Up:    Request{Src: src, Dst: s.toWildCard(src)},
			Cores: []Request{{Src: s.toWildCard(src), Dst: s.toWildCard(r.Dst)}},
			Down:  Request{Src: s.toWildCard(r.Dst), Dst: r.Dst},
		}, nil
	}
}
