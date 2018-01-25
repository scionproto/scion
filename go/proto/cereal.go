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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
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
func WriteRoot(c Cerealizable, b common.RawBytes) (int, error) {
	msg, err := cerealInsert(c)
	if err != nil {
		return 0, err
	}
	raw := &util.Raw{B: b}
	enc := capnp.NewPackedEncoder(raw)
	if err := enc.Encode(msg); err != nil {
		return 0, common.NewBasicError("Failed to encode capnp struct", err,
			"id", c.ProtoId(), "type", common.TypeOf(c))
	}
	return raw.Offset, nil
}

// PackRoot creates a complete capnp message for c, and returns it encoded as bytes.
func PackRoot(c Cerealizable) (common.RawBytes, error) {
	msg, err := cerealInsert(c)
	if err != nil {
		return nil, err
	}
	raw, err := msg.MarshalPacked()
	if err != nil {
		return nil, common.NewBasicError("Failed to marshal capnp struct", err,
			"id", c.ProtoId(), "type", common.TypeOf(c))
	}
	return raw, nil
}

func cerealInsert(c Cerealizable) (*capnp.Message, error) {
	msg, arena, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, common.NewBasicError("Failed to create new capnp message", err,
			"id", c.ProtoId(), "type", common.TypeOf(c))
	}
	s, err := NewRootStruct(c.ProtoId(), arena)
	if err != nil {
		return nil, err
	}
	if err := pogs.Insert(uint64(c.ProtoId()), s, c); err != nil {
		return nil, common.NewBasicError("Failed to insert struct into capnp message", err,
			"id", c.ProtoId(), "type", common.TypeOf(c))
	}
	return msg, nil
}

// ReadRootFromRaw returns the root struct from a capnp message encoded in b.
func ReadRootFromRaw(b common.RawBytes) (capnp.Struct, error) {
	return ReadRootFromReader(bytes.NewBuffer(b))
}

// ReadRootFromReader returns the root struct from a capnp message read from r.
func ReadRootFromReader(r io.Reader) (_ capnp.Struct, err error) {
	// Convert capnp panics to errors
	defer func() {
		if rec := recover(); rec != nil {
			err = common.NewBasicError("capnp panic", nil, "panic", rec)
		}
	}()
	var blank capnp.Struct
	msg, err := capnp.NewPackedDecoder(r).Decode()
	if err != nil {
		return blank, common.NewBasicError("Failed to decode capnp message", err)
	}
	rootPtr, err := msg.RootPtr()
	if err != nil {
		return blank, common.NewBasicError("Failed to get root pointer from capnp message", err)
	}
	return rootPtr.Struct(), nil
}

// ParseStruct parses a capnp struct into a Cerealizable instance.
func ParseStruct(c Cerealizable, pType ProtoIdType, s capnp.Struct) error {
	if err := pogs.Extract(c, uint64(pType), s); err != nil {
		return common.NewBasicError("Failed to extract struct from capnp message", err)
	}
	return nil
}

// ParseFromRaw is a utility function, which reads a capnp message from b and parses it into c.
// It is effectively a composition of ReadRootFromRaw and ParseStruct.
func ParseFromRaw(c Cerealizable, pType ProtoIdType, b common.RawBytes) error {
	return ParseFromReader(c, pType, bytes.NewBuffer(b))
}

// ParseFromReader is a utility function, which reads a capnp message from r and parses it into c.
// It is effectively a composition of ReadRootFromReader and ParseStruct.
func ParseFromReader(c Cerealizable, pType ProtoIdType, r io.Reader) error {
	s, err := ReadRootFromReader(r)
	if err != nil {
		return err
	}
	return ParseStruct(c, pType, s)
}
