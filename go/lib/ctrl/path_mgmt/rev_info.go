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

// This file contains the Go representation of a revocation info.

package path_mgmt

import (
	"fmt"
	"time"

	//log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

const MinRevTTL = 10 * time.Second // Revocation MinRevTTL

var _ proto.Cerealizable = (*RevInfo)(nil)

type RevInfo struct {
	IfID      uint64
	RawIsdas  addr.IAInt     `capnp:"isdas"`
	LinkType  proto.LinkType // Link type of revocation
	Timestamp uint32         // Time in seconds since unix epoch
	RevTTL    uint32         // Validity period of the revocation in seconds
}

func NewRevInfoFromRaw(b common.RawBytes) (*RevInfo, error) {
	r := &RevInfo{}
	return r, proto.ParseFromRaw(r, r.ProtoId(), b)
}

func (r *RevInfo) IA() addr.IA {
	return r.RawIsdas.IA()
}

func (r *RevInfo) Valid() bool {
	assert.Must(r.RevTTL >= uint32(MinRevTTL.Seconds()), "RevTTL must not be smaller than MinRevTTL")
	now := uint32(time.Now().Second())
	// Revocation is not valid if its timestamp is not within the MinRevTTL
	if r.Timestamp > now || r.Timestamp < now-r.RevTTL {
		return false
	}
	return true
}

func (r *RevInfo) ProtoId() proto.ProtoIdType {
	return proto.RevInfo_TypeID
}

func (r *RevInfo) String() string {
	return fmt.Sprintf("IA: %s IfID: %d Link type: %s Timestamp: %s TTL: %d",
		r.IA(), r.IfID, r.LinkType, util.TimeToString(uint64(r.Timestamp)), r.RevTTL)
}
