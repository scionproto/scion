// Copyright 2018 ETH Zurich
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

package log

import (
	"fmt"
	"math/rand/v2"
)

// DebugID is used to correlate behavior in logs. A DebugID is allocated
// for each outgoing request/response or notify message exchange, and for each
// handler executed during ListenAndServe.
type DebugID uint32

// NewDebugID creates a new debug id.
func NewDebugID() DebugID {
	return DebugID(rand.Uint32())
}

func (id DebugID) String() string {
	return fmt.Sprintf("%08x", uint32(id))
}
