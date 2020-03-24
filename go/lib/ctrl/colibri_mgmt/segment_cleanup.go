// Copyright 2020 ETH Zurich, Anapaya Systems
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

package colibri_mgmt

import (
	"github.com/scionproto/scion/go/proto"
)

type SegmentCleanup struct {
	ID    *SegmentReservationID `capnp:"id"`
	Index uint8
}

func (s *SegmentCleanup) ProtoId() proto.ProtoIdType {
	return proto.SegmentCleanupData_TypeID
}
