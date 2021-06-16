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

package pathdb

import (
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/ctrl/seg"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

// PackSegment packs a path segment.
func PackSegment(ps *seg.PathSegment) ([]byte, error) {
	return proto.Marshal(seg.PathSegmentToPB(ps))
}

// UnpackSegment unpacks a path segment.
func UnpackSegment(raw []byte) (*seg.PathSegment, error) {
	var pb cppb.PathSegment
	if err := proto.Unmarshal(raw, &pb); err != nil {
		return nil, err
	}
	return seg.SegmentFromPB(&pb)
}
