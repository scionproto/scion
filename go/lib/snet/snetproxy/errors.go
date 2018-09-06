// Copyright 2018 ETH Zurich
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

package snetproxy

import (
	"io"
	"net"
	"os"
	"syscall"

	"github.com/scionproto/scion/go/lib/common"
)

const (
	ErrDispatcherDead            = "dispatcher dead"
	ErrLocalAddressChanged       = "local address changed on reconnect"
	ErrBindAddressChanged        = "bind address changed on reconnect"
	ErrReconnecterTimeoutExpired = "Timeout expired"
	ErrReconnecterStopped        = "Stop method was called"
	ErrClosed                    = "closed"
)

func isDispatcherError(err error) bool {
	err = extractNestedError(err)
	// On Linux, the following errors should prompt a reconnect:
	//   - An EOF, when a Read happens to a connection that was closed at the
	//   other end, and there is no outstanding outgoing data.
	//   - An EPIPE, when a Write happens to a connection that was closed at
	//   the other end.
	//   - An ECONNRESET, when a Read happens to a connection that was
	//   closed at the other end, and there is outstanding outgoing data. An
	//   ECONNRESET may be followed by EOF on repeated attempts.
	if err == io.EOF ||
		isSpecificSysError(err, syscall.EPIPE) ||
		isSpecificSysError(err, syscall.ECONNRESET) {
		return true
	}
	// All other errors can be immediately propagated back to the application.
	return false
}

// extractNestedError returns the innermost error of err.
func extractNestedError(err error) error {
	if nestedError := common.GetNestedError(err); nestedError != nil {
		return nestedError
	}
	return err
}

func isSpecificSysError(err error, errno syscall.Errno) bool {
	serr, ok := getSysError(err)
	if !ok {
		return false
	}
	return serr.Err == errno
}

func isSysError(err error) bool {
	_, ok := getSysError(err)
	return ok
}

func getSysError(err error) (*os.SyscallError, bool) {
	nerr, ok := err.(*net.OpError)
	if !ok {
		return nil, false
	}
	serr, ok := nerr.Err.(*os.SyscallError)
	if !ok {
		return nil, false
	}
	return serr, true
}
