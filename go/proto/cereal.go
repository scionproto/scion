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

	capnp "zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
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
func WriteRoot(c Cerealizable, b []byte) (int, error) {
	msg, err := cerealInsert(c)
	if err != nil {
		return 0, err
	}
	raw := &util.Raw{B: b}
	enc := capnp.NewPackedEncoder(raw)
	if err := enc.Encode(msg); err != nil {
		return 0, serrors.WrapStr("Failed to encode capnp struct", err,
			"id", c.ProtoId(), "type", common.TypeOf(c))
	}
	return raw.Offset, nil
}

// PackRoot creates a complete capnp message for c, and returns it encoded as bytes.
func PackRoot(c Cerealizable) ([]byte, error) {
	msg, err := cerealInsert(c)
	if err != nil {
		return nil, err
	}
	raw, err := msg.MarshalPacked()
	if err != nil {
		return nil, serrors.WrapStr("Failed to marshal capnp struct", err,
			"id", c.ProtoId(), "type", common.TypeOf(c))
	}
	return raw, nil
}

// SerializeTo writes a Cerealizable object to an io.Writer.
func SerializeTo(c Cerealizable, wr io.Writer) error {
	msg, err := cerealInsert(c)
	if err != nil {
		return err
	}
	if err := capnp.NewPackedEncoder(wr).Encode(msg); err != nil {
		return err
	}
	return nil
}

func cerealInsert(c Cerealizable) (*capnp.Message, error) {
	msg, arena, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, serrors.WrapStr("Failed to create new capnp message", err,
			"id", c.ProtoId(), "type", common.TypeOf(c))
	}
	s, err := NewRootStruct(c.ProtoId(), arena)
	if err != nil {
		return nil, err
	}
	if err := pogs.Insert(uint64(c.ProtoId()), s, c); err != nil {
		return nil, serrors.WrapStr("Failed to insert struct into capnp message", err,
			"id", c.ProtoId(), "type", common.TypeOf(c))
	}
	return msg, nil
}

// ParseFromRaw is a utility function, which reads a capnp message from b and parses it into c.
func ParseFromRaw(c Cerealizable, b []byte) error {
	return ParseFromReader(c, bytes.NewBuffer(b))
}

// ParseFromReader is a utility function, which reads a capnp message from r and parses it into c.
func ParseFromReader(c Cerealizable, r io.Reader) error {
	s, err := readRootFromReader(r)
	if err != nil {
		return err
	}
	return SafeExtract(c, uint64(c.ProtoId()), s)
}

// readRootFromReader returns the root struct from a capnp message read from r.
func readRootFromReader(r io.Reader) (capnp.Struct, error) {
	var blank capnp.Struct
	msg, err := SafeDecode(capnp.NewPackedDecoder(r))
	if err != nil {
		return blank, serrors.WrapStr("Failed to decode capnp message", err)
	}
	rootPtr, err := msg.RootPtr()
	if err != nil {
		return blank, serrors.WrapStr("Failed to get root pointer from capnp message", err)
	}
	return rootPtr.Struct(), nil
}

// SafeExtract calls pogs.Extract, converting panics to errors.
func SafeExtract(val interface{}, typeID uint64, s capnp.Struct) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = serrors.New("pogs panic", "panic", rec)
		}
	}()
	return pogsExtractF(val, typeID, s)
}

var pogsExtractF = pogs.Extract

// SafeDecode calls the decode method on the argument, converting panics to
// errors.
func SafeDecode(decoder *capnp.Decoder) (msg *capnp.Message, err error) {
	// FIXME(scrye): Add unit tests for this function.
	defer func() {
		if rec := recover(); rec != nil {
			msg, err = nil, serrors.New("decode panic", "panic", rec)
		}
	}()
	return decoder.Decode()
}
