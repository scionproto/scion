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

package segreq

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Splitter splits requests for the PS.
type Splitter struct {
	ASInspector infra.ASInspector
}

func (s *Splitter) Split(ctx context.Context,
	r segfetcher.Request) (segfetcher.RequestSet, error) {

	srcCore, err := s.isCore(ctx, r.Src)
	if err != nil {
		return segfetcher.RequestSet{}, err
	}
	dstCore, err := s.isCore(ctx, r.Dst)
	if err != nil {
		return segfetcher.RequestSet{}, err
	}
	switch {
	case !srcCore && dstCore:
		return segfetcher.RequestSet{Up: r}, nil
	case srcCore && dstCore:
		return segfetcher.RequestSet{Cores: segfetcher.Requests{r}}, nil
	case srcCore && !dstCore:
		return segfetcher.RequestSet{Down: r}, nil
	default:
		return segfetcher.RequestSet{}, segfetcher.ErrInvalidRequest
	}
}

func (s *Splitter) isCore(ctx context.Context, ia addr.IA) (bool, error) {
	if ia.IsZero() {
		return false, serrors.WithCtx(segfetcher.ErrInvalidRequest, "reason", "empty ia")
	}
	if ia.IsWildcard() {
		return true, nil
	}
	args := infra.ASInspectorOpts{
		RequiredAttributes: []infra.Attribute{infra.Core},
	}
	isCore, err := s.ASInspector.HasAttributes(ctx, ia, args)
	if err != nil {
		return false, err
	}
	return isCore, nil
}
