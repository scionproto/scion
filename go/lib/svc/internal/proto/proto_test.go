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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSVCResolutionPogsSerialization tests that serializing and deserializing
// via pogs returns the initial object.
func TestSVCResolutionPogsSerialization(t *testing.T) {
	// Sanity check to test that the Go reflection helper type is in sync with
	// the capnp data definition.
	message := SVCResolutionReply{
		Transports: []Transport{
			{Key: "foo", Value: "bar"},
			{Key: "bar", Value: "baz"},
		},
	}
	buffer := &bytes.Buffer{}

	err := message.SerializeTo(buffer)
	require.NoError(t, err)

	var newMessage SVCResolutionReply
	err = newMessage.DecodeFrom(buffer)
	require.NoError(t, err)
	assert.Equal(t, message, newMessage)
}

// TestSVCResolutionReplyString tests that the String function writes the correct data.
func TestSVCResolutionReplyString(t *testing.T) {
	message := SVCResolutionReply{
		Transports: []Transport{
			{Key: "foo", Value: "bar"},
			{Key: "bar", Value: "baz"},
		},
	}
	assert.Equal(t, "SVCResolutionReply([foo:bar bar:baz])", message.String())
}
