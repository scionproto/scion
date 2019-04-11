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

// Package proto implements helpers for capnp SVC address resolution messages.
package proto

import (
	"io"

	capnp "zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"

	"github.com/scionproto/scion/go/proto"
)

// SVCResolutionReply is a pogs-compatible representation of a list of
// SCION transport key-value pairs.
type SVCResolutionReply struct {
	Transports []Transport
}

func (r *SVCResolutionReply) SerializeTo(wr io.Writer) error {
	msg, arena, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return err
	}
	root, err := proto.NewRootSVCResolutionResponse(arena)
	if err != nil {
		return err
	}
	if err := pogs.Insert(proto.SVCResolutionResponse_TypeID, root.Struct, r); err != nil {
		return err
	}
	if err := capnp.NewEncoder(wr).Encode(msg); err != nil {
		return err
	}
	return nil
}

func (r *SVCResolutionReply) DecodeFrom(rd io.Reader) error {
	msg, err := capnp.NewDecoder(rd).Decode()
	if err != nil {
		return err
	}
	root, err := msg.RootPtr()
	if err != nil {
		return err
	}
	if err := pogs.Extract(r, proto.SVCResolutionResponse_TypeID, root.Struct()); err != nil {
		return err
	}
	return nil
}

// Transport is a pogs-compatible representation of a protocol transport
// key-value pair.
type Transport struct {
	Key   string
	Value string
}
