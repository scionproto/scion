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
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
)

// Beacon consists of the path segment and the interface it was received on.
type Beacon struct {
	// Segment is the path segment.
	Segment *seg.PathSegment
	// InIfId is the interface the beacon is received on.
	InIfId common.IFIDType
}

// Diversity returns the link diversity between this and the other beacon. The
// link diversity indicates the number of links in this beacon that do not
// appear in the other beacon. If the other beacon has no segment set, 0 is
// returned. Note: Diversity is asymmetric.
func (b Beacon) Diversity(other Beacon) int {
	if b.Segment == nil || other.Segment == nil {
		return 0
	}
	var diff int
	for _, asEntry := range b.Segment.ASEntries {
		ia, ifid := link(asEntry)
		var found bool
		for _, otherEntry := range other.Segment.ASEntries {
			oia, oifid := link(otherEntry)
			if ia.Equal(oia) && ifid == oifid {
				found = true
				break
			}
		}
		if !found {
			diff++
		}
	}
	return diff
}

func (b Beacon) String() string {
	return fmt.Sprintf("Ingress: %d Segment: [ %s ]", b.InIfId, b.Segment)
}

func link(entry seg.ASEntry) (addr.IA, common.IFIDType) {
	return entry.Local, common.IFIDType(entry.HopEntry.HopField.ConsIngress)
}

// BeaconOrErr contains a read-only beacon or an error.
type BeaconOrErr struct {
	Beacon Beacon
	Err    error
}

// RevocationOrErr contains a signed revocation or an error.
type RevocationOrErr struct {
	Rev *path_mgmt.SignedRevInfo
	Err error
}
