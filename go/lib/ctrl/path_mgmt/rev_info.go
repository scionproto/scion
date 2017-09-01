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

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ proto.Cerealizable = (*RevInfo)(nil)

type RevInfo struct {
	IfID     uint64
	Epoch    uint64
	Nonce    common.RawBytes
	Siblings []SiblingHash
	PrevRoot common.RawBytes
	NextRoot common.RawBytes
	RawIsdas uint32 `capnp:"isdas"`
	HashType uint16
}

func NewRevInfoFromRaw(b common.RawBytes) (*RevInfo, *common.Error) {
	r := &RevInfo{}
	return r, proto.ParseFromRaw(r, r.ProtoId(), b)
}

func (r *RevInfo) IA() *addr.ISD_AS {
	return addr.IAFromInt(int(r.RawIsdas))
}
func (r *RevInfo) ProtoId() proto.ProtoIdType {
	return proto.RevInfo_TypeID
}

func (r *RevInfo) String() string {
	return fmt.Sprintf("IA: %v IfID: %v Epoch: %v", r.IA(), r.IfID, r.Epoch)
}

type SiblingHash struct {
	IsLeft bool
	Hash   common.RawBytes
}
