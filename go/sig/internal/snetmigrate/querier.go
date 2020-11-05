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

package snetmigrate

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
)

// PathQuerier implements snet.PathQuerier. This struct just exists to simplify
// the refactoring (prevent dep loops) and in the end pathmgr should be removed
// or as a step in between implement snet.PathQuerier directly.
type PathQuerier struct {
	Resolver   pathmgr.Resolver
	PathPolicy *pathpol.Policy
	IA         addr.IA
}

func (q *PathQuerier) Query(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	if q.Resolver == nil || dst.Equal(q.IA) {
		return []snet.Path{&emptyPath{q.IA}}, nil
	}
	var paths []snet.Path
	if q.PathPolicy == nil {
		paths = q.Resolver.Query(ctx, q.IA, dst, sciond.PathReqFlags{})
	} else {
		paths = q.Resolver.QueryFilter(ctx, q.IA, dst, q.PathPolicy)
	}
	if len(paths) == 0 {
		return nil, common.NewBasicError("unable to find paths", nil)
	}
	return paths, nil
}
