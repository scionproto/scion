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
	"context"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

const (
	// ErrReadingRows is the error message in case we fail to read more from
	// the database.
	ErrReadingRows common.ErrMsg = "Failed to read rows"
	// ErrParse is the error message in case the parsing a db entry fails.
	ErrParse common.ErrMsg = "Failed to parse entry"
)

// InsertStats provides statistics about an insertion.
type InsertStats struct {
	Inserted, Updated, Filtered int
}

// DB defines the interface that all beacon DB backends have to implement.
type DB interface {
	// CandidateBeacons returns up to `setSize` beacons that are allowed for the
	// given usage. The beacons in the slice are ordered by segment length from
	// shortest to longest.
	CandidateBeacons(ctx context.Context, setSize int, usage Usage, src addr.IA) ([]Beacon, error)
	// BeaconSources returns all source ISD-AS of the beacons in the database.
	BeaconSources(ctx context.Context) ([]addr.IA, error)
	// Insert inserts a beacon with its allowed usage into the database.
	InsertBeacon(ctx context.Context, beacon Beacon, usage Usage) (InsertStats, error)
}

const (
	// UsageUpReg indicates the beacon is allowed to be registered as an up segment.
	UsageUpReg Usage = 0x01
	// UsageDownReg indicates the beacon is allowed to be registered as a down segment.
	UsageDownReg Usage = 0x02
	// UsageCoreReg indicates the beacon is allowed to be registered as a core segment.
	UsageCoreReg Usage = 0x04
	// UsageProp indicates the beacon is allowed to be propagated.
	UsageProp Usage = 0x08
)

// Usage indicates what the beacon is allowed to be used for according to the policies.
type Usage int

// UsageFromPolicyType maps the policy type to the usage flag.
func UsageFromPolicyType(policyType PolicyType) Usage {
	switch policyType {
	case UpRegPolicy:
		return UsageUpReg
	case DownRegPolicy:
		return UsageDownReg
	case CoreRegPolicy:
		return UsageCoreReg
	case PropPolicy:
		return UsageProp
	default:
		panic(fmt.Sprintf("Invalid policyType: %v", policyType))
	}
}

// None indicates whether the beacons is not allowed to be used anywhere.
func (u Usage) None() bool {
	return u&0x0F == 0
}

func (u Usage) String() string {
	names := []string{}
	if u&UsageUpReg != 0 {
		names = append(names, "UpRegistration")
	}
	if u&UsageDownReg != 0 {
		names = append(names, "DownRegistration")
	}
	if u&UsageCoreReg != 0 {
		names = append(names, "CoreRegistration")
	}
	if u&UsageProp != 0 {
		names = append(names, "Propagation")
	}
	return fmt.Sprintf("Usage: [%s]", strings.Join(names, ","))
}

// PackBeacon packs a beacon.
func PackBeacon(ps *seg.PathSegment) ([]byte, error) {
	return proto.Marshal(seg.PathSegmentToPB(ps))
}

// UnpackBeacon unpacks a beacon.
func UnpackBeacon(raw []byte) (*seg.PathSegment, error) {
	var pb cppb.PathSegment
	if err := proto.Unmarshal(raw, &pb); err != nil {
		return nil, err
	}
	return seg.BeaconFromPB(&pb)
}
