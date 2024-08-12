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
	"math/rand"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/pathdb"
	"github.com/scionproto/scion/private/pathdb/query"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/trust"
)

// Pather computes the remote address with a path based on the provided segment.
type Pather interface {
	GetPath(svc addr.SVC, ps *seg.PathSegment) (*snet.SVCAddr, error)
}

// CoreChecker checks whether a given ia is core.
type CoreChecker struct {
	Inspector trust.Inspector
}

// IsCore checks whether ia is a wildcard or core
func (c *CoreChecker) IsCore(ctx context.Context, ia addr.IA) (bool, error) {
	if ia.IsWildcard() {
		return true, nil
	}
	return c.Inspector.HasAttributes(ctx, ia, trust.Core)
}

// SegSelector selects segments to use for a connection to a remote server.
type SegSelector struct {
	PathDB   pathdb.DB
	RevCache revcache.RevCache
	Pather   Pather
}

// SelectSeg selects a suitable segment for the given path db query.
func (s *SegSelector) SelectSeg(ctx context.Context,
	params *query.Params) (snet.Path, error) {

	res, err := s.PathDB.Get(ctx, params)
	if err != nil {
		return nil, err
	}
	segs := res.Segs()
	_, err = segs.FilterSegs(func(ps *seg.PathSegment) (bool, error) {
		return revcache.NoRevokedHopIntf(ctx, s.RevCache, ps)
	})
	if err != nil {
		return nil, serrors.Wrap("failed to filter segments", err)
	}
	if len(segs) < 1 {
		return nil, serrors.New("no segments found")
	}
	seg := segs[rand.Intn(len(segs))]

	svcaddr, err := s.Pather.GetPath(addr.SvcCS, seg)
	// odd interface, builds address not path. Use GetPath to convert to snet.Path
	if err != nil {
		return nil, err
	}
	return svcaddr.GetPath()
}
