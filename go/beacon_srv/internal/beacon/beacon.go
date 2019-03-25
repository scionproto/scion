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

package beacon

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
)

// Beacon consists of the path segment and the interface it was received on.
type Beacon struct {
	// Segment is the path segment.
	Segment *seg.PathSegment
	// InIfId is the interface the beacon is received on.
	InIfId common.IFIDType
}

// BeaconOrErr contains a read-only beacon or an error.
type BeaconOrErr struct {
	Beacon Beacon
	Err    error
}
