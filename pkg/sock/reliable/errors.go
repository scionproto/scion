// Copyright 2018 ETH Zurich, Anapaya Systems
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

package reliable

import (
	"errors"
	"io"
	"syscall"

	"github.com/scionproto/scion/pkg/private/common"
)

// Possible errors
var (
	ErrNoAddress             common.ErrMsg = "no address found"
	ErrNoPort                common.ErrMsg = "missing port"
	ErrPayloadTooLong        common.ErrMsg = "payload too long"
	ErrIncompleteFrameHeader common.ErrMsg = "incomplete frame header"
	ErrBadFrameLength        common.ErrMsg = "bad frame length"
	ErrBadCookie             common.ErrMsg = "bad cookie"
	ErrBadAddressType        common.ErrMsg = "bad address type"
	ErrIncompleteAddress     common.ErrMsg = "incomplete IP address"
	ErrIncompletePort        common.ErrMsg = "incomplete UDP port"
	ErrIncompleteMessage     common.ErrMsg = "incomplete message"
	ErrBadLength             common.ErrMsg = "bad length"
	ErrBufferTooSmall        common.ErrMsg = "buffer too small"
)

func IsDispatcherError(err error) bool {
	// On Linux, the following errors should prompt a reconnect:
	//   - An EOF, when a Read happens to a connection that was closed at the
	//   other end, and there is no outstanding outgoing data.
	//   - An EPIPE, when a Write happens to a connection that was closed at
	//   the other end.
	//   - An ECONNRESET, when a Read happens to a connection that was
	//   closed at the other end, and there is outstanding outgoing data. An
	//   ECONNRESET may be followed by EOF on repeated attempts.
	// All other errors can be immediately propagated back to the application.
	return errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET)
}
