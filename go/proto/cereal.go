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

package proto

import (
	"bytes"
	"fmt"

	"zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
)

type Cerealizable interface {
	fmt.Stringer
	ProtoId() ProtoIdType
	ProtoType() fmt.Stringer
	NewStruct(interface{}) (capnp.Struct, *common.Error)
}

type CerealBase struct {
	Cerealizable
}

func NewCerealBase(c Cerealizable) CerealBase {
	return CerealBase{c}
}

func (cb *CerealBase) Len() int {
	// Len is not supported on capnp object
	return -1
}

func (cb *CerealBase) Copy() (common.Payload, *common.Error) {
	return nil, common.NewError("Copy isn't supported on capnp payloads, yet")
}

func (cb *CerealBase) ParseRaw(b common.RawBytes) *common.Error {
	msg, err := capnp.NewPackedDecoder(bytes.NewBuffer(b)).Decode()
	if err != nil {
		return common.NewError("Failed to decode base capnp message",
			"type", cb.ProtoType(), "err", err)
	}
	rootPtr, err := msg.RootPtr()
	if err != nil {
		return common.NewError("Failed to get root pointer from base capnp message",
			"type", cb.ProtoType(), "err", err)
	}
	return cb.ParseProto(rootPtr.Struct())
}

func (cb *CerealBase) ParseProto(s capnp.Struct) *common.Error {
	if err := pogs.Extract(cb.Cerealizable, uint64(cb.ProtoId()), s); err != nil {
		return common.NewError("Failed to extract struct from capnp message",
			"type", cb.ProtoType(), "err", err)
	}
	return nil
}

func (cb *CerealBase) Write(b common.RawBytes) (int, *common.Error) {
	msg, cerr := cb.packMsg()
	if cerr != nil {
		return 0, cerr
	}
	raw := &util.Raw{B: b}
	enc := capnp.NewPackedEncoder(raw)
	if err := enc.Encode(msg); err != nil {
		return 0, common.NewError("Failed to encode base capnp struct",
			"type", cb.ProtoType(), "err", err)
	}
	return raw.Offset, nil
}

func (cb *CerealBase) PackRaw() (common.RawBytes, *common.Error) {
	msg, cerr := cb.packMsg()
	if cerr != nil {
		return nil, cerr
	}
	packed, err := msg.MarshalPacked()
	if err != nil {
		return nil, common.NewError("Failed to marshal base capnp struct",
			"type", cb.ProtoType(), "err", err)
	}
	return packed, nil
}

func (cb *CerealBase) packMsg() (*capnp.Message, *common.Error) {
	msg, arena, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, common.NewError("Failed to create new base capnp message",
			"type", cb.ProtoType(), "err", err)
	}
	if cerr := cb.PackProto(arena); err != nil {
		return nil, cerr
	}
	return msg, nil
}

func (cb *CerealBase) PackProto(arena *capnp.Segment) *common.Error {
	s, cerr := cb.NewStruct(arena)
	if cerr != nil {
		return cerr
	}
	return cb.Insert(s)
}

func (cb *CerealBase) Insert(s capnp.Struct) *common.Error {
	if err := pogs.Insert(uint64(cb.ProtoId()), s, cb.Cerealizable); err != nil {
		return common.NewError("Failed to insert struct into capnp message",
			"type", cb.ProtoType(), "err", err)
	}
	return nil
}
