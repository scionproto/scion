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

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/svc/internal/proto"
)

func TestSVCResolutionSerialization(t *testing.T) {
	// Sanity check to test that the decoder/serializer operate correctly.
	t.Run("Serializing and deserializing should return the initial object", func(t *testing.T) {
		message := Reply{
			Transports: map[Transport]string{
				"foo": "bar",
				"bar": "baz",
			},
		}
		buffer := &bytes.Buffer{}

		err := message.SerializeTo(buffer)
		assert.NoError(t, err)

		var newMessage Reply
		err = newMessage.DecodeFrom(buffer)
		assert.NoError(t, err)
		assert.Equal(t, message, newMessage)
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

	t.Run("Replies should be converted to the correct proto objects", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.Name, func(t *testing.T) {
				protoReply := tc.Reply.toProtoFormat()
				assert.Equal(t, tc.ExpectedProtoReply, protoReply)
			})
		}
	})
}

func TestReplyFromProtoFormat(t *testing.T) {
	testCases := []struct {
		Name          string
		ProtoReply    *proto.SVCResolutionReply
		ExpectedReply *Reply
		Error         assert.ErrorAssertionFunc
	}{
		{
			Name:       "nil capnp object",
			ProtoReply: nil,
			ExpectedReply: &Reply{
				Transports: make(map[Transport]string),
			},
			Error: assert.NoError,
		},
		{
			Name:       "reply with nil slice",
			ProtoReply: &proto.SVCResolutionReply{},
			ExpectedReply: &Reply{
				Transports: make(map[Transport]string),
			},
			Error: assert.NoError,
		},
		{
			Name: "reply with empty slice",
			ProtoReply: &proto.SVCResolutionReply{
				Transports: []proto.Transport{},
			},
			ExpectedReply: &Reply{
				Transports: make(map[Transport]string),
			},
			Error: assert.NoError,
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
			Error: assert.NoError,
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
			Error: assert.NoError,
		},
		{
			Name: "duplicate keys",
			ProtoReply: &proto.SVCResolutionReply{
				Transports: []proto.Transport{
					{Key: "foo", Value: "bar"},
					{Key: "foo", Value: "baz"},
				},
			},
			ExpectedReply: &Reply{
				Transports: map[Transport]string{
					"foo": "bar",
				},
			},
			Error: assert.Error,
		},
	}
	t.Run("Proto objects should be converted to the correct reply", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.Name, func(t *testing.T) {
				var reply Reply
				err := reply.fromProtoFormat(tc.ProtoReply)
				tc.Error(t, err)
				assert.Equal(t, tc.ExpectedReply, &reply)
			})
		}
	})
	t.Run("Initializing from a proto object should reset state", func(t *testing.T) {
		reply := &Reply{
			Transports: map[Transport]string{
				"foo": "bar",
			},
		}
		err := reply.fromProtoFormat(nil)
		assert.NoError(t, err)
		assert.Equal(t, &Reply{Transports: make(map[Transport]string)}, reply)
	})
}
