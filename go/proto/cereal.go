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

// ProtoIdType represents a capnp struct Id.
type ProtoIdType uint64

func (p ProtoIdType) String() string {
	return fmt.Sprintf("0x%x", uint64(p))
}

// Cerealizable represents a type which has a corresponding Cap'n Proto (capnp)
// representation, and supports pogs insertion/extraction.
type Cerealizable interface {
	fmt.Stringer
	ProtoId() ProtoIdType
}

// WriteRoot creates a complete capnp message for c, and writes it out to b.
// The int return value is the number of bytes written.
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

// PackRoot creates a complete capnp message for c, and returns it encoded as bytes.
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

// ReadRootFromRaw returns the root struct from a capnp message encoded in b.
func ReadRootFromRaw(b common.RawBytes) (capnp.Struct, *common.Error) {
	return ReadRootFromReader(bytes.NewBuffer(b))
}

// ReadRootFromReader returns the root struct from a capnp message read from r.
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

// ParseStruct parses a capnp struct into a Cerealizable instance.
func ParseStruct(c Cerealizable, pType ProtoIdType, s capnp.Struct) *common.Error {
	if err := pogs.Extract(c, uint64(pType), s); err != nil {
		return common.NewError("Failed to extract struct from capnp message", "err", err)
	}
	return nil
}

// ParseFromRaw is a utility function, which reads a capnp message from b and parses it into c.
// It is effectively a composition of ReadRootFromRaw and ParseStruct.
func ParseFromRaw(c Cerealizable, pType ProtoIdType, b common.RawBytes) *common.Error {
	return ParseFromReader(c, pType, bytes.NewBuffer(b))
}

// ParseFromReader is a utility function, which reads a capnp message from r and parses it into c.
// It is effectively a composition of ReadRootFromReader and ParseStruct.
func ParseFromReader(c Cerealizable, pType ProtoIdType, r io.Reader) *common.Error {
	s, cerr := ReadRootFromReader(r)
	if cerr != nil {
		return cerr
	}
	return ParseStruct(c, pType, s)
}
