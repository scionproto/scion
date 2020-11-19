// Copyright 2020 Anapaya Systems
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

package segutil

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/snet"
)

// Router returns paths backed by the local path database.
// XXX(matzf): this doesn't do meaningful work anymore, drop it.
type Router struct {
	Pather segfetcher.Pather
}

// Route returns a path from the local AS to dst. If dst matches the local
// AS, an empty path is returned.
func (r *Router) Route(ctx context.Context, dst addr.IA) (snet.Path, error) {
	paths, err := r.AllRoutes(ctx, dst)
	if err != nil || len(paths) == 0 {
		return nil, err
	}
	return paths[0], nil
}

// AllRoutes is similar to Route except that it returns multiple paths.
func (r *Router) AllRoutes(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	return r.Pather.GetPaths(ctx, dst, false)
}
