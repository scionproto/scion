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

package util

import (
	"fmt"
	"math/rand"
)

// TraceID is used to correlate behavior in logs. A TraceID is allocated
// for each outgoing request/response or notify message exchange, and for each
// handler executed during ListenAndServe.
type TraceID uint32

func GetTraceID() TraceID {
	return TraceID(rand.Uint32())
}

func (id TraceID) String() string {
	return fmt.Sprintf("%08x", uint32(id))
}
