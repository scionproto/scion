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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/proto"
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

// ParseRaw populates the non-capnp fields of s based on data from the raw
// capnp fields.
func (s *SegReply) ParseRaw() error {
	for i, segMeta := range s.Recs.Recs {
		if err := segMeta.Segment.ParseRaw(); err != nil {
			return common.NewBasicError("Unable to parse segment", err, "seg_index", i,
				"segment", segMeta.Segment)
		}
	}
	return nil
}

// Sanitize returns a fresh SegReply containing only the segments and
// revocations in s that could be parsed successfully. Note that pointers in
// the returned value reference the same memory as s.
//
// Since Sanitize is always successful, pass in a logger to be informed of any
// discarded objects. If logger is nil, no logging is performed and the reply
// is silently sanitized.
func (s *SegReply) Sanitize(logger log.Logger) *SegReply {
	newReply := &SegReply{
		Req:  s.Req,
		Recs: &SegRecs{},
	}
	for _, segment := range s.Recs.Recs {
		err := segment.Segment.WalkHopEntries()
		if err != nil {
			if logger != nil {
				logger.Warn("Discarding bad segment", err, "segment", segment)
			}
		} else {
			newReply.Recs.Recs = append(newReply.Recs.Recs, segment)
		}
	}
	for _, revocation := range s.Recs.SRevInfos {
		_, err := revocation.RevInfo()
		if err != nil {
			if logger != nil {
				logger.Warn("Discarding bad revocation", "revocation", revocation, "err", err)
			}
		} else {
			newReply.Recs.SRevInfos = append(newReply.Recs.SRevInfos, revocation)
		}
	}
	return newReply
}
