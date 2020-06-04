// Copyright 2020 ETH Zurich, Anapaya Systems
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

package reservation

import (
	"time"

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
)

// Request is the base type for all Requests, both segment and E2E.
type Request struct {
	// TODO(juagargi) question for @roosd: we need to store the path the packet is using,
	// so that we can forward this packet to the next hop? Plus we need to know the ingress and
	// egress interfaces of it. Is spath.Path a good type for this?
	Path      spath.Path // the path the packet came with
	Timestamp time.Time  // the mandatory timestamp
}

// NewRequest constructs the base Request type.
func NewRequest(ts time.Time, path *spath.Path) (*Request, error) {
	if path == nil {
		return nil, serrors.New("new request with nil path")
	}
	return &Request{
		Timestamp: ts,
		Path:      *path.Copy(),
	}, nil
}
