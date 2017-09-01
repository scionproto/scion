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
	"io"

	//log "github.com/inconshreveable/log15"
	"zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
)

type Struct interface {
	// Added by gen.go
	GetStruct() capnp.Struct
}

type CtxWrite func(Cerealizable, common.RawBytes) (int, *common.Error)

type Cerealizable interface {
	fmt.Stringer
	ProtoId() ProtoIdType
}

func WriteRoot(c Cerealizable, b common.RawBytes) (int, *common.Error) {
	msg, cerr := cerealInsert(c)
	if cerr != nil {
		return 0, cerr
	}
	raw := &util.Raw{B: b}
	enc := capnp.NewPackedEncoder(raw)
	if err := enc.Encode(msg); err != nil {
		return 0, common.NewError("Failed to encode capnp struct",
			"id", c.ProtoId(), "type", common.TypeOf(c), "err", err)
	}
	return raw.Offset, nil
}

func PackRoot(c Cerealizable) (common.RawBytes, *common.Error) {
	msg, cerr := cerealInsert(c)
	if cerr != nil {
		return nil, cerr
	}
	raw, err := msg.MarshalPacked()
	if err != nil {
		return nil, common.NewError("Failed to marshal capnp struct",
			"id", c.ProtoId(), "type", common.TypeOf(c), "err", err)
	}
	return raw, nil
}

func cerealInsert(c Cerealizable) (*capnp.Message, *common.Error) {
	msg, arena, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, common.NewError("Failed to create new capnp message",
			"id", c.ProtoId(), "type", common.TypeOf(c), "err", err)
	}
	s, cerr := NewRootStruct(c.ProtoId(), arena)
	if cerr != nil {
		return nil, cerr
	}
	if err := pogs.Insert(uint64(c.ProtoId()), s, c); err != nil {
		return nil, common.NewError("Failed to insert struct into capnp message",
			"id", c.ProtoId(), "type", common.TypeOf(c), "err", err)
	}
	return msg, nil
}

func ReadRootFromRaw(b common.RawBytes) (capnp.Struct, *common.Error) {
	return ReadRootFromReader(bytes.NewBuffer(b))
}

func ReadRootFromReader(r io.Reader) (capnp.Struct, *common.Error) {
	var blank capnp.Struct
	msg, err := capnp.NewPackedDecoder(r).Decode()
	if err != nil {
		return blank, common.NewError("Failed to decode capnp message", "err", err)
	}
	rootPtr, err := msg.RootPtr()
	if err != nil {
		return blank, common.NewError("Failed to get root pointer from capnp message", "err", err)
	}
	return rootPtr.Struct(), nil
}

func ParseStruct(v interface{}, pType ProtoIdType, s capnp.Struct) *common.Error {
	if err := pogs.Extract(v, uint64(pType), s); err != nil {
		return common.NewError("Failed to extract struct from capnp message", "err", err)
	}
	return nil
}

func ParseFromRaw(v interface{}, pType ProtoIdType, b common.RawBytes) *common.Error {
	return ParseFromReader(v, pType, bytes.NewBuffer(b))
}

func ParseFromReader(v interface{}, pType ProtoIdType, r io.Reader) *common.Error {
	s, cerr := ReadRootFromReader(r)
	if cerr != nil {
		return cerr
	}
	return ParseStruct(v, pType, s)
}
