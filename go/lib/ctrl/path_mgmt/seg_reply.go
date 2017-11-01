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

// This file contains the Go representation of segment replies.

package path_mgmt

import (
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ proto.Cerealizable = (*SegReply)(nil)

type SegReply struct {
	Req  *SegReq
	Recs *SegRecs
}

func NewSegReplyFromRaw(b common.RawBytes) (*SegReply, error) {
	s := &SegReply{}
	return s, proto.ParseFromRaw(s, s.ProtoId(), b)
}

func (s *SegReply) ProtoId() proto.ProtoIdType {
	return proto.SegReply_TypeID
}

func (s *SegReply) Write(b common.RawBytes) (int, error) {
	return proto.WriteRoot(s, b)
}

func (s *SegReply) String() string {
	return fmt.Sprintf("Req: %s Reply:\n%s", s.Req, s.Recs)
}
