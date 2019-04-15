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

package proto

import (
	"bytes"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSVCResolutionPogsSerialization(t *testing.T) {
	// Sanity check to test that the Go reflection helper type is in sync with
	// the capnp data definition.
	Convey("Serializing and deserializing via pogs should return the initial object", t, func() {
		message := SVCResolutionReply{
			Transports: []Transport{
				{Key: "foo", Value: "bar"},
				{Key: "bar", Value: "baz"},
			},
		}
		buffer := &bytes.Buffer{}

		err := message.SerializeTo(buffer)
		SoMsg("serialize error", err, ShouldBeNil)

		var newMessage SVCResolutionReply
		err = newMessage.DecodeFrom(buffer)
		SoMsg("decode error", err, ShouldBeNil)
		SoMsg("data", newMessage, ShouldResemble, message)
	})
}

func TestSVCResolutionReplyString(t *testing.T) {
	Convey("String function should write correct data", t, func() {
		message := SVCResolutionReply{
			Transports: []Transport{
				{Key: "foo", Value: "bar"},
				{Key: "bar", Value: "baz"},
			},
		}
		So(message.String(), ShouldEqual, "SVCResolutionReply([foo:bar bar:baz])")
	})
}
