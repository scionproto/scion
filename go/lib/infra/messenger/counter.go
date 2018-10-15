// Copyright 2018 ETH Zurich, Anapaya Systems
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

package messenger

import (
	"sync/atomic"

	"github.com/scionproto/scion/go/lib/scrypto"
)

var (
	counter = scrypto.RandUint64()
)

// NextId is a concurrency-safe generator of unique request IDs for the messenger.
func NextId() uint64 {
	return atomic.AddUint64(&counter, 1)
}
