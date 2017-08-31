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

package query

import (
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl/seg"
)

// TODO(shitz): This should be moved when we have hidden path sets.
type SegLabel []byte

var NullLabel = []byte{0, 0, 0, 0, 0, 0, 0, 0}

type IntfSpec struct {
	IA   *addr.ISD_AS
	IfID uint64
}

type Params struct {
	SegID    common.RawBytes
	SegTypes []uint8
	Labels   []uint64
	Intfs    []*IntfSpec
	StartsAt []*addr.ISD_AS
	EndsAt   []*addr.ISD_AS
}

type Result struct {
	Seg    *seg.PathSegment
	Labels []SegLabel
}
