// Copyright 2024 SCION Association
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

package router

// Fnv1aOffset32 is the FNV-1a offset basis, an initial state for [HashFNV1a].
const Fnv1aOffset32 uint32 = 2166136261

// HashFNV1a returns the hash of state combined with byte c.
// To hash a byte sequence, call it once per byte and pass each result as the next state.
// Start from [Fnv1aOffset32], or better, from an earlier result such as a seed.
func HashFNV1a(state uint32, c byte) uint32 {
	const prime32 = 16777619
	return (state ^ uint32(c)) * prime32
}
