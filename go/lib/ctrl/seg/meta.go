// Copyright 2017 ETH Zurich
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

package seg

import (
	"fmt"

	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

// Meta holds the path segment with its type.
type Meta struct {
	Segment *PathSegment
	Type    Type
}

// Type is the path segment type.
type Type int

// Path segment types.
const (
	TypeUp   = Type(cppb.SegmentType_SEGMENT_TYPE_UP)
	TypeDown = Type(cppb.SegmentType_SEGMENT_TYPE_DOWN)
	TypeCore = Type(cppb.SegmentType_SEGMENT_TYPE_CORE)
)

func (t Type) String() string {
	switch t {
	case TypeUp:
		return "up"
	case TypeDown:
		return "down"
	case TypeCore:
		return "core"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}
