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

// fnv1aOffset32 is an initial offset that can be used as initial state when calling
// hashFNV1a.
const fnv1aOffset32 uint32 = 2166136261

// hashFNV1a returns a hash value for the given initial state combined with the given byte.
// To get a hash for a sequence of bytes, invoke for each byte, passing the returned value
// of one call as the state for the next. Example. s1 = hashFNV1a(fnv1aOffset, byte1)
// s2 = hashFNV1a(s1, byte2) etc. It is valid and recommended to use a value obtained
// from calla to hashFNV1a() as the initial state rather than fnv1aOffset32 itself.
func hashFNV1a(state uint32, c byte) uint32 {
	const prime32 = 16777619
	return (state ^ uint32(c)) * prime32
}
