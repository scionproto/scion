// Copyright 2020 ETH Zurich
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
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/pkg/trust"
)

// NewSplitter creates a segfetcher.Splitter for a segfetcher.Pather used in the path service.
func NewSplitter(ia addr.IA, core bool, inspector trust.Inspector,
	pathDB pathdb.PathDB) segfetcher.Splitter {

	return &splitter{
		Splitter: &segfetcher.MultiSegmentSplitter{
			LocalIA:   ia,
			Core:      core,
			Inspector: inspector,
		},
		expander: &wildcardExpander{
			localIA:   ia,
			core:      core,
			inspector: inspector,
			pathDB:    pathDB,
		},
	}
}

// splitter is a segfetcher.Splitter for a segfetcher.Pather used in the path service.
// The default splittler returns a list of (up to three) wildcard segment requests.
// These wildcards are normally resolved by segreq.forwarder, the AS-local
// segment request handler.
// However, segment requests _by_ the control server itself don't pass through
// this forwarding handler, so this custom splitter is used to expand wildcard
// requests.
type splitter struct {
	segfetcher.Splitter
	expander *wildcardExpander
}

// Split splits a path request from the local AS to dst into a set of segment
// requests.
func (s *splitter) Split(ctx context.Context, dst addr.IA) (segfetcher.Requests, error) {
	wcReqs, err := s.Splitter.Split(ctx, dst)
	if err != nil {
		return nil, err
	}

	var reqs segfetcher.Requests
	for _, req := range wcReqs {
		expanded, err := s.expander.ExpandSrcWildcard(ctx, req)
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, expanded...)
	}
	return reqs, nil
}
