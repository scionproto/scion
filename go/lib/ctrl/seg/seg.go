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

// This file contains the Go representation of a Path Segment

package seg

import (
	"bytes"

	"zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/proto"
)

var _ common.Payload = (*PathSegment)(nil)

type Meta struct {
	Type    uint8
	Segment PathSegment `capnp:"pcb"`
}

type PathSegment struct {
	Info      []byte
	IfID      uint64
	ASEntries []ASEntry `capnp:"asms"`
	Exts      struct {
		Sibra []byte `capnp:"-"` // Omit SIBRA extension for now.
	}
}

func NewPathSegmentFromRaw(b common.RawBytes) (*PathSegment, *common.Error) {
	msg, err := capnp.NewPackedDecoder(bytes.NewBuffer(b)).Decode()
	if err != nil {
		return nil, common.NewError("Failed to parse PathSegment", "err", err)
	}
	rootPtr, err := msg.RootPtr()
	if err != nil {
		return nil, common.NewError("Failed to parse PathSegment", "err", err)
	}
	seg := &PathSegment{}
	err = pogs.Extract(seg, proto.PathSegment_TypeID, rootPtr.Struct())
	if err != nil {
		return nil, common.NewError("Failed to parse PathSegment", "err", err)
	}
	return seg, nil
}

func (ps *PathSegment) Len() int {
	// The length can't be calculated until the payload is packed.
	return -1
}

func (ps *PathSegment) Copy() (common.Payload, *common.Error) {
	rawPld, err := ps.Pack()
	if err != nil {
		return nil, err
	}
	return NewPathSegmentFromRaw(rawPld)
}

func (ps *PathSegment) Pack() (common.RawBytes, *common.Error) {
	message, arena, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, common.NewError("Failed to pack PathSegment", "err", err)
	}
	root, err := proto.NewRootPathSegment(arena)
	if err != nil {
		return nil, common.NewError("Failed to pack PathSegment", "err", err)
	}
	if err := pogs.Insert(proto.PathSegment_TypeID, root.Struct, ps); err != nil {
		return nil, common.NewError("Failed to pack PathSegment", "err", err)
	}
	packed, err := message.MarshalPacked()
	if err != nil {
		return nil, common.NewError("Failed to pack PathSegment", "err", err)
	}
	return packed, nil
}

func (ps *PathSegment) Write(b common.RawBytes) (int, *common.Error) {
	packed, err := ps.Pack()
	if err != nil {
		return 0, nil
	}
	if len(b) < len(packed) {
		return 0, common.NewError("Provided buffer is not large enough",
			"expected", len(packed), "have", len(b))
	}
	copy(b, packed)
	return len(packed), nil
}

func (ps *PathSegment) String() string {
	// TODO(shitz): Implement
	return "PathSegment"
}
