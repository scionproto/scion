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

package svc

import (
	"io"
	"sort"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/svc/internal/proto"
)

// Reply is an SVC resolution reply.
type Reply struct {
	// Transports maps transport keys (e.g., "QUIC" or "UDP") to network
	// address strings (e.g., "192.168.1.1:80"). Applications should check if
	// the transport keys are acceptable and must parse the address strings
	// accordingly.
	Transports map[string]string
}

// DecodeFrom decodes a reply message from its capnp representation.
func (r *Reply) DecodeFrom(rd io.Reader) error {
	var protoObject proto.SVCResolutionReply
	if err := protoObject.DecodeFrom(rd); err != nil {
		return err
	}
	return r.FromProtoFormat(&protoObject)
}

// SerializeTo encodes a reply message into its capnp representation.
func (r *Reply) SerializeTo(wr io.Writer) error {
	return r.ToProtoFormat().SerializeTo(wr)
}

// ToProtoFormat converts a reply message to a low-level format suitable for
// network exchanges. The serializer uses this under the hood to convert the
// reply message to a byte stream.
//
// A nil high-level object will produce a capnp object with an empty slice. A
// high-level object with a nil or empty map will produce a capnp object with
// an empty slice.
//
// Elements of the slice are always sorted by Key in ascending order.
func (r *Reply) ToProtoFormat() *proto.SVCResolutionReply {
	protoReply := &proto.SVCResolutionReply{Transports: []proto.Transport{}}
	if r == nil || len(r.Transports) == 0 {
		return protoReply
	}
	for k, v := range r.Transports {
		protoReply.Transports = append(protoReply.Transports, proto.Transport{Key: k, Value: v})
	}
	sort.Slice(protoReply.Transports, func(i, j int) bool {
		return protoReply.Transports[i].Key < protoReply.Transports[j].Key
	})
	return protoReply
}

// FromProtoFormat converts from a low-level format suitable for network
// exchanges to a reply message. The decoder uses this under the hood to
// convert a byte stream to a reply message.
//
// A nil protoObject will produce a reply with an empty map. A protoObject
// with a nil or empty slice will produce a reply with an empty map.
// Duplicate keys will result in an error. Unknown keys are silently added to
// the map.
func (r *Reply) FromProtoFormat(protoReply *proto.SVCResolutionReply) error {
	r.Transports = make(map[string]string)
	if protoReply == nil || len(protoReply.Transports) == 0 {
		return nil
	}
	for _, transport := range protoReply.Transports {
		if _, ok := r.Transports[transport.Key]; ok {
			return common.NewBasicError("duplicate key not allowed", nil, "key", transport.Key)
		}
		r.Transports[transport.Key] = transport.Value
	}
	return nil
}
