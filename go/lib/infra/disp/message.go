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

package disp

import (
	"github.com/scionproto/scion/go/lib/common"
)

// MessageAdapter converts application level messages to and from elements the
// Dispatcher understands.
type MessageAdapter interface {
	// Convert msg to a format suitable for sending on a wire
	MsgToRaw(msg Message) (common.RawBytes, error)
	// Convert a raw byte slice to a message
	RawToMsg(common.RawBytes) (Message, error)
	// Return a key used to match requests and replies
	MsgKey(Message) string
}

// Generic object used by the Dispatcher.
type Message interface{}
