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
	"bytes"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/svc/internal/proto"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestSVCResolutionSerialization(t *testing.T) {
	// Sanity check to test that the decoder/serializer operate correctly.
	Convey("Serializing and deserializing should return the initial object", t, func() {
		message := Reply{
			Transports: map[Transport]string{
				"foo": "bar",
				"bar": "baz",
			},
		}
		buffer := &bytes.Buffer{}

		err := message.SerializeTo(buffer)
		SoMsg("serialize error", err, ShouldBeNil)

		var newMessage Reply
		err = newMessage.DecodeFrom(buffer)
		SoMsg("decode error", err, ShouldBeNil)
		SoMsg("message", newMessage, ShouldResemble, message)
	})
}

func TestReplyToProtoFormat(t *testing.T) {
	testCases := []struct {
		Name               string
		Reply              *Reply
		ExpectedProtoReply *proto.SVCResolutionReply
	}{
		{
			Name:  "nil reply",
			Reply: nil,
			ExpectedProtoReply: &proto.SVCResolutionReply{
				Transports: []proto.Transport{},
			},
		},
		{
			Name:  "reply with nil map",
			Reply: &Reply{},
			ExpectedProtoReply: &proto.SVCResolutionReply{
				Transports: []proto.Transport{},
			},
		},
		{
			Name:  "reply with empty map",
			Reply: &Reply{Transports: make(map[Transport]string)},
			ExpectedProtoReply: &proto.SVCResolutionReply{
				Transports: []proto.Transport{},
			},
		},
		{
			Name: "reply with map with two elements",
			Reply: &Reply{
				Transports: map[Transport]string{
					"foo": "bar",
					"bar": "baz",
				},
			},
			ExpectedProtoReply: &proto.SVCResolutionReply{
				Transports: []proto.Transport{
					{Key: "bar", Value: "baz"},
					{Key: "foo", Value: "bar"},
				},
			},
		},
	}

	Convey("Replies should be converted to the correct proto objects", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				protoReply := tc.Reply.toProtoFormat()
				So(protoReply, ShouldResemble, tc.ExpectedProtoReply)
			})
		}
	})
}

func TestReplyFromProtoFormat(t *testing.T) {
	testCases := []struct {
		Name          string
		ProtoReply    *proto.SVCResolutionReply
		ExpectedReply *Reply
		ExpectedError bool
	}{
		{
			Name:       "nil capnp object",
			ProtoReply: nil,
			ExpectedReply: &Reply{
				Transports: make(map[Transport]string),
			},
		},
		{
			Name:       "reply with nil slice",
			ProtoReply: &proto.SVCResolutionReply{},
			ExpectedReply: &Reply{
				Transports: make(map[Transport]string),
			},
		},
		{
			Name: "reply with empty slice",
			ProtoReply: &proto.SVCResolutionReply{
				Transports: []proto.Transport{},
			},
			ExpectedReply: &Reply{
				Transports: make(map[Transport]string),
			},
		},
		{
			Name: "reply with one element",
			ProtoReply: &proto.SVCResolutionReply{
				Transports: []proto.Transport{
					{Key: "foo", Value: "bar"},
				},
			},
			ExpectedReply: &Reply{
				Transports: map[Transport]string{
					"foo": "bar",
				},
			},
		},
		{
			Name: "reply with two elements with different keys",
			ProtoReply: &proto.SVCResolutionReply{
				Transports: []proto.Transport{
					{Key: "foo", Value: "bar"},
					{Key: "bar", Value: "baz"},
				},
			},
			ExpectedReply: &Reply{
				Transports: map[Transport]string{
					"foo": "bar",
					"bar": "baz",
				},
			},
		},
		{
			Name: "duplicate keys",
			ProtoReply: &proto.SVCResolutionReply{
				Transports: []proto.Transport{
					{Key: "foo", Value: "bar"},
					{Key: "foo", Value: "baz"},
				},
			},
			ExpectedError: true,
		},
	}
	Convey("Proto objects should be converted to the correct reply", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				var reply Reply
				err := reply.fromProtoFormat(tc.ProtoReply)
				xtest.SoMsgError("err", err, tc.ExpectedError)
				if !tc.ExpectedError {
					SoMsg("reply", &reply, ShouldResemble, tc.ExpectedReply)
				}
			})
		}
	})
	Convey("Initializing from a proto object should reset state", t, func() {
		reply := &Reply{
			Transports: map[Transport]string{
				"foo": "bar",
			},
		}
		err := reply.fromProtoFormat(nil)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("data", reply, ShouldResemble, &Reply{Transports: make(map[Transport]string)})
	})
}
