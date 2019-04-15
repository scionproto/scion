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
	"fmt"
	"io"

	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*SVCResolutionReply)(nil)

// SVCResolutionReply is a pogs-compatible representation of a list of
// SCION transport key-value pairs.
type SVCResolutionReply struct {
	Transports []Transport
}

func (r *SVCResolutionReply) SerializeTo(wr io.Writer) error {
	return proto.SerializeTo(r, wr)
}

func (r *SVCResolutionReply) DecodeFrom(rd io.Reader) error {
	return proto.ParseFromReader(r, rd)
}

func (*SVCResolutionReply) ProtoId() proto.ProtoIdType {
	return proto.SVCResolutionReply_TypeID
}

func (r *SVCResolutionReply) String() string {
	return fmt.Sprintf("SVCResolutionReply(%v)", r.Transports)
}

// Transport is a pogs-compatible representation of a protocol transport
// key-value pair.
type Transport struct {
	Key   string
	Value string
}

func (t Transport) String() string {
	return fmt.Sprintf("%s:%s", t.Key, t.Value)
}
