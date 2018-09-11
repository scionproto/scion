// Copyright 2018 Anapaya Systems
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

package path_mgmt

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*SegChangesIdReq)(nil)

type SegChangesIdReq struct {
	LastCheck uint32
}

func (s *SegChangesIdReq) ProtoId() proto.ProtoIdType {
	return proto.SegChangesIdReq_TypeID
}

func (s *SegChangesIdReq) String() string {
	return fmt.Sprintf("LastCheck: %d", s.LastCheck)
}

type SegIds struct {
	SegId  common.RawBytes
	FullId common.RawBytes
}

var _ proto.Cerealizable = (*SegChangesIdReply)(nil)

type SegChangesIdReply struct {
	Ids []*SegIds
}

func (s *SegChangesIdReply) ProtoId() proto.ProtoIdType {
	return proto.SegChangesIdReply_TypeID
}

func (s *SegChangesIdReply) String() string {
	return fmt.Sprintf("Ids: %v", s.Ids)
}

var _ proto.Cerealizable = (*SegChangesReq)(nil)

type SegChangesReq struct {
	SegIds []common.RawBytes
}

func (s *SegChangesReq) ProtoId() proto.ProtoIdType {
	return proto.SegChangesReq_TypeID
}

func (s *SegChangesReq) String() string {
	return fmt.Sprintf("SegIds: %v", s.SegIds)
}

var _ proto.Cerealizable = (*SegChangesReply)(nil)

type SegChangesReply struct {
	*SegRecs
}
