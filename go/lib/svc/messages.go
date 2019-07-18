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
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/svc/internal/proto"
)

// Reply is an SVC resolution reply.
type Reply struct {
	// Transports maps transport keys (e.g., "QUIC" or "UDP") to network
	// address strings (e.g., "192.168.1.1:80"). Applications should check if
	// the transport keys are acceptable and must parse the address strings
	// accordingly.
	Transports map[Transport]string
	// ReturnPath contains the reversed and initialized path the SVC resolution
	// message arrived on. This can be used to communicate across paths
	// bootstrapped via One-Hop Path communication.
	ReturnPath snet.Path
}

// DecodeFrom decodes a reply message from its capnp representation. No
// validation of transport keys is performed.
//
// If the returned error is non-nil, the state of Reply is unspecified.
func (r *Reply) DecodeFrom(rd io.Reader) error {
	var protoObject proto.SVCResolutionReply
	if err := protoObject.DecodeFrom(rd); err != nil {
		return err
	}
	return r.fromProtoFormat(&protoObject)
}

// SerializeTo encodes a reply message into its capnp representation. No
// validation of transport keys is performed.
func (r *Reply) SerializeTo(wr io.Writer) error {
	return r.toProtoFormat().SerializeTo(wr)
}

// toProtoFormat converts a reply message to a low-level format suitable for
// network exchanges. The serializer uses this under the hood to convert the
// reply message to a byte stream.
//
// A nil high-level object will produce a capnp object with an empty slice. A
// high-level object with a nil or empty map will produce a capnp object with
// an empty slice. Unknown Transport keys are included in the Reply.
//
// Elements of the slice are always sorted by Key in ascending order.
func (r *Reply) toProtoFormat() *proto.SVCResolutionReply {
	protoReply := &proto.SVCResolutionReply{Transports: []proto.Transport{}}
	if r == nil || len(r.Transports) == 0 {
		return protoReply
	}
	for k, v := range r.Transports {
		protoReply.Transports = append(protoReply.Transports,
			proto.Transport{Key: string(k), Value: v})
	}
	sort.Slice(protoReply.Transports, func(i, j int) bool {
		return protoReply.Transports[i].Key < protoReply.Transports[j].Key
	})
	return protoReply
}

// fromProtoFormat converts from a low-level format suitable for network
// exchanges to a reply message. The decoder uses this under the hood to
// convert a byte stream to a reply message.
//
// A nil protoObject will produce a reply with an empty map. A protoObject
// with a nil or empty slice will produce a reply with an empty map.
// Duplicate keys will result in an error. Unknown keys are silently added to
// the map.
//
// Calling this function always resets the internal state of the Reply, even if
// an error is returned.
func (r *Reply) fromProtoFormat(protoReply *proto.SVCResolutionReply) error {
	r.Transports = make(map[Transport]string)
	if protoReply == nil || len(protoReply.Transports) == 0 {
		return nil
	}
	for _, transport := range protoReply.Transports {
		if _, ok := r.Transports[Transport(transport.Key)]; ok {
			return common.NewBasicError("duplicate key not allowed", nil, "key", transport.Key)
		}
		r.Transports[Transport(transport.Key)] = transport.Value
	}
	return nil
}

// Transport contains constants for common transport keys.
type Transport string

const (
	UDP  Transport = "UDP"
	QUIC Transport = "QUIC"
)
