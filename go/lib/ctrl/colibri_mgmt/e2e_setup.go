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

type E2ESetup struct {
	Base              *E2EBase
	SegmentRsvs       []SegmentReservationID
	SegmentRsvASCount []uint8
	RequestedBW       uint8
	AllocationTrail   []uint8
	Which             proto.E2ESetupReqData_Which
	Success           *E2ESetupReqSuccess
	Failure           *E2ESetupReqFailure
}

func (s *E2ESetup) ProtoId() proto.ProtoIdType {
	return proto.E2ESetupReqData_TypeID
}

type E2ESetupReqSuccess struct {
	Token []byte
}

type E2ESetupReqFailure struct {
	ErrorCode uint8
}

type E2ESetupRes struct {
	Base    *E2EBase
	Which   proto.E2ESetupResData_Which
	Success *E2ESetupSuccess
	Failure *E2ESetupFailure
}

func (s *E2ESetupRes) ProtoId() proto.ProtoIdType {
	return proto.E2ESetupResData_TypeID
}

type E2ESetupSuccess struct {
	Token []byte
}

type E2ESetupFailure struct {
	ErrorCode       uint8
	AllocationTrail []uint8
}
