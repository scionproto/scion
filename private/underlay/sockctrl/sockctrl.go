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

//go:build go1.9
// +build go1.9

// This version of sockctrl is for Go versions >= 1.9, where the socket FDs are
// accessible via RawConn.Control().
package sockctrl

import (
	"net"

	"github.com/scionproto/scion/pkg/private/serrors"
)

func SockControl(c *net.UDPConn, f func(int) error) error {
	rawConn, err := c.SyscallConn()
	if err != nil {
		return serrors.WrapStr("sockctrl: error accessing raw connection", err)
	}
	var ctrlErr error
	err = rawConn.Control(func(fd uintptr) {
		ctrlErr = f(int(fd))
	})
	if err != nil {
		return serrors.WrapStr("sockctrl: RawConn.Control error", err)
	}
	if ctrlErr != nil {
		return serrors.WrapStr("sockctrl: control function error", ctrlErr)
	}
	return nil
}
