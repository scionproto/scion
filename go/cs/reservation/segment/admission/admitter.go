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

package admission

import (
	"context"

	"github.com/scionproto/scion/go/cs/reservation/segment"
)

// Admitter specifies what an admission entity has to implement to govern the segment admission.
type Admitter interface {
	// req will be modified with the allowed and maximum bandwidths if they were computed.
	// It can also return an error.
	AdmitRsv(ctx context.Context, req *segment.SetupReq) error
}
