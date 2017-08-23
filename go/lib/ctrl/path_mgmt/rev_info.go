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
	"bytes"
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/addr"

	"zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ common.Payload = (*RevInfo)(nil)

type SiblingHash struct {
	IsLeft bool
	Hash   common.RawBytes
}

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
	msg, err := capnp.NewPackedDecoder(bytes.NewBuffer(b)).Decode()
	if err != nil {
		return nil, common.NewError("Failed to parse RevInfo", "err", err)
	}
	rootPtr, err := msg.RootPtr()
	if err != nil {
		return nil, common.NewError("Failed to parse RevInfo", "err", err)
	}
	info := &RevInfo{}
	err = pogs.Extract(info, proto.RevInfo_TypeID, rootPtr.Struct())
	if err != nil {
		return nil, common.NewError("Failed to parse RevInfo", "err", err)
	}
	return info, nil
}

func (r *RevInfo) IA() *addr.ISD_AS {
	return addr.IAFromInt(int(r.RawIsdas))
}

func (r *RevInfo) Len() int {
	// The length can't be calculated until the payload is packed.
	return -1
}

func (r *RevInfo) Copy() (common.Payload, *common.Error) {
	rawPld, err := r.Pack()
	if err != nil {
		return nil, err
	}
	return NewRevInfoFromRaw(rawPld)
}

func (r *RevInfo) Pack() (common.RawBytes, *common.Error) {
	message, arena, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, common.NewError("Failed to pack RevInfo", "err", err)
	}
	root, err := proto.NewRootRevInfo(arena)
	if err != nil {
		return nil, common.NewError("Failed to pack RevInfo", "err", err)
	}
	if err := pogs.Insert(proto.RevInfo_TypeID, root.Struct, r); err != nil {
		return nil, common.NewError("Failed to pack RevInfo", "err", err)
	}
	packed, err := message.MarshalPacked()
	if err != nil {
		return nil, common.NewError("Failed to pack RevInfo", "err", err)
	}
	return packed, nil
}

func (r *RevInfo) Write(b common.RawBytes) (int, *common.Error) {
	packed, err := r.Pack()
	if err != nil {
		return 0, common.NewError("Failed to write RevInfo", "err", err)
	}
	if len(b) < len(packed) {
		return 0, common.NewError("Provided buffer is not large enough",
			"expected", len(packed), "have", len(b))
	}
	copy(b, packed)
	return len(packed), nil
}

func (r *RevInfo) String() string {
	return fmt.Sprintf("IA: %v IfID: %v Epoch: %v", r.IA(), r.IfID, r.Epoch)
}
