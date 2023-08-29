// Copyright 2019 ETH Zurich, Anapaya Systems
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

package snet

import (
	"context"

	"github.com/scionproto/scion/pkg/addr"
)

type PathQuerier interface {
	Query(context.Context, addr.IA) ([]Path, error)
}

// Router performs path resolution for SCION-speaking applications.
//
// Most applications backed by SCIOND can use the default router implementation
// in this package. Applications that run SCIOND-less (PS, SD, BS) might be
// interested in spinning their own implementations.
type Router interface {
	// Route returns a path from the local AS to dst. If dst matches the local
	// AS, an empty path is returned.
	Route(ctx context.Context, dst addr.IA) (Path, error)
	// AllRoutes is similar to Route except that it returns multiple paths.
	AllRoutes(ctx context.Context, dst addr.IA) ([]Path, error)
}

type BaseRouter struct {
	Querier PathQuerier
}

// Route uses the specified path resolver (if one exists) to obtain a path from
// the local AS to dst.
func (r *BaseRouter) Route(ctx context.Context, dst addr.IA) (Path, error) {
	paths, err := r.AllRoutes(ctx, dst)
	if err != nil || len(paths) == 0 {
		return nil, err
	}
	return paths[0], nil
}

// AllRoutes is the same as Route except that it returns multiple paths.
func (r *BaseRouter) AllRoutes(ctx context.Context, dst addr.IA) ([]Path, error) {
	return r.Querier.Query(ctx, dst)
}
