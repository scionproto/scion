// Copyright 2019 ETH Zurich
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
	"strings"

	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/proto"
)

type HPSegReply struct {
	Recs []*HPSegRecs
}

func (hs *HPSegReply) ProtoId() proto.ProtoIdType {
	return proto.HPSegReply_TypeID
}

func (hs *HPSegReply) String() string {
	desc := []string{}
	for _, r := range hs.Recs {
		desc = append(desc, r.String())
	}
	return strings.Join(desc, "\n")
}

// ParseRaw populates the non-capnp fields of s based on data from the raw
// capnp fields.
func (hs *HPSegReply) ParseRaw() error {
	for _, r := range hs.Recs {
		if r != nil {
			err := r.ParseRaw()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Sanitize returns a fresh HPSegReply containing only the segments and
// revocations in s that could be parsed successfully. Note that pointers in
// the returned value reference the same memory as s.
//
// Since Sanitize is always successful, pass in a logger to be informed of any
// discarded objects. If logger is nil, no logging is performed and the reply
// is silently sanitized.
func (hs *HPSegReply) Sanitize(logger log.Logger) *HPSegReply {
	newReply := &HPSegReply{
		Recs: []*HPSegRecs{},
	}
	if hs.Recs == nil {
		return newReply
	}
	for _, r := range hs.Recs {
		temp := &HPSegRecs{
			GroupId: r.GroupId,
			Recs:    []*seg.Meta{},
		}
		for _, segment := range r.Recs {
			temp.Recs = append(temp.Recs, segment)
		}
		if len(temp.Recs) > 0 {
			newReply.Recs = append(newReply.Recs, temp)
		}
	}
	return newReply
}
