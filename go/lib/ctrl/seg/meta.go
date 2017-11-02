// Copyright 2017 ETH Zurich
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

package seg

import (
	"fmt"
)

type Meta struct {
	Type    Type
	Segment PathSegment `capnp:"pcb"`
}

func (m *Meta) String() string {
	return fmt.Sprintf("Type: %v, Segment: %v", m.Type, m.Segment)
}

type Type uint8

const (
	UpSegment   Type = 0
	DownSegment Type = 1
	CoreSegment Type = 2
)

func (t Type) String() string {
	switch t {
	case UpSegment:
		return "UP"
	case DownSegment:
		return "DOWN"
	case CoreSegment:
		return "CORE"
	}
	return fmt.Sprintf("UNKNOWN (%d)", t)
}
