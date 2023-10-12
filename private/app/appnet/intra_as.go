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

package appnet

import (
	"context"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	rawpath "github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

// IntraASPathQuerier implements the PathQuerier interface. It will only provide
// AS-internal paths, i.e., zero-hops paths with only the IA as destination. This
// should only be used in places where you know that you only need to
// communicate inside the AS. The type of Path returned is a complete
// implementation with proper metadata.
type IntraASPathQuerier struct {
	IA  addr.IA
	MTU uint16
}

// Query implements PathQuerier.
func (q IntraASPathQuerier) Query(_ context.Context, _ addr.IA) ([]snet.Path, error) {
	return []snet.Path{path.Path{
		Src:           q.IA,
		Dst:           q.IA,
		DataplanePath: path.Empty{},
		Meta: snet.PathMetadata{
			MTU:    q.MTU,
			Expiry: time.Now().Add(rawpath.MaxTTL),
		},
	}}, nil
}
