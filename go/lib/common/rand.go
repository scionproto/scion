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

package common

import (
	"crypto/rand"
	mrand "math/rand"
)

func RandUint64() uint64 {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// If this happens, there's some serious problem with the runtime or
		// OS, and there's nothing we can do about it.
		panic("No random numbers available")
	}
	return NativeOrder.Uint64(b)
}

func RandInt64() int64 {
	return int64(RandUint64())
}

func init() {
	// Make sure math/rand's default generator is seeded with a random value on start.
	mrand.Seed(RandInt64())
}
