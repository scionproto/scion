// Copyright 2019 Anapaya Systems
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

package segfetcher

import "github.com/scionproto/scion/go/lib/ctrl/seg"

// Segments is a set of up, core, and down segments.
type Segments struct {
	Up   seg.Segments
	Core seg.Segments
	Down seg.Segments
}

// Add adds the other segments to the current segments.
func (s *Segments) Add(other Segments) {
	s.Up = append(s.Up, other.Up...)
	s.Core = append(s.Core, other.Core...)
	s.Down = append(s.Down, other.Down...)
}
