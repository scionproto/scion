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

// Package path implements snet.Path with full metadata
// This is used by libraries that provide paths for applications to use, such
// as the path combinator and the SCION Daemon API. Applications using snet will not
// usually make use of this package directly.
//
// This component implements a path querier that returns only paths
// within the local AS in the form of a standard Path with metadata
// but zero hops.

package path

import (
	"context"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	rawpath "github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/snet"
)

// IntraASPathQuerier implements the PathQuerier interface. It will only provide
// AS internal paths, i.e., empty paths with only the IA as destination. This
// should only be used in places where you know that you only need to
// communicate inside the AS.
type IntraASPathQuerier struct {
	IA  addr.IA
	MTU uint16
}

// Query implements PathQuerier.
func (q IntraASPathQuerier) Query(_ context.Context, _ addr.IA) ([]snet.Path, error) {
	return []snet.Path{Path{
		Src: q.IA,
		Dst: q.IA,
		Meta: snet.PathMetadata{
			MTU:    q.MTU,
			Expiry: time.Now().Add(rawpath.MaxTTL * time.Second),
		},
	}}, nil
}
