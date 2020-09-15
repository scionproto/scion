// Copyright 2020 Anapaya Systems
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
	"math"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

// Info represents the path segment information.
type Info struct {
	// Raw contains the encoded path segment information. It is used for
	// signature input and must not be modified.
	Raw []byte
	// Timestamp is the path segment creation time.
	Timestamp time.Time
	// SegmentID is the segment ID used in data plane hop field computation.
	SegmentID uint16

	// ISD is deprecated and only used for legacy path construction.
	ISD addr.ISD
}

// infoFromRaw decodes the protobuf representation. The byte slice is captured
// and must not be modifed.
func infoFromRaw(raw []byte) (Info, error) {
	var pb cppb.SegmentInformation
	if err := proto.Unmarshal(raw, &pb); err != nil {
		return Info{}, err
	}
	if pb.SegmentId > math.MaxUint16 {
		return Info{}, serrors.New("segment ID overflows uint16", "segment_id", pb.SegmentId)
	}
	return Info{
		Raw:       raw,
		SegmentID: uint16(pb.SegmentId),
		Timestamp: time.Unix(pb.Timestamp, 0),
		ISD:       addr.ISD(pb.DeprecatedIsd),
	}, nil
}

// NewInfo creates a new path segment info.
func NewInfo(timestamp time.Time, segmentID uint16, isd addr.ISD) (Info, error) {
	info := &cppb.SegmentInformation{
		Timestamp:     timestamp.Unix(),
		SegmentId:     uint32(segmentID),
		DeprecatedIsd: uint32(isd),
	}
	raw, err := proto.Marshal(info)
	if err != nil {
		return Info{}, err
	}
	return Info{
		Raw:       raw,
		Timestamp: time.Unix(info.Timestamp, 0),
		SegmentID: segmentID,
		ISD:       isd,
	}, nil
}

func (info Info) String() string {
	return fmt.Sprintf("Timestamp: %s SegmentID %x", info.Timestamp, info.SegmentID)
}
