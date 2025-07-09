// Copyright 2025 Anapaya Systems
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

package slices

func Transform[In any, Out any](in []In, transform func(In) Out) []Out {
	if in == nil {
		return nil
	}
	out := make([]Out, 0, len(in))
	for _, v := range in {
		out = append(out, transform(v))
	}
	return out
}
