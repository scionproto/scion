// Copyright 2024 ETH Zurich
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

// In Windows, SetSockOptInt and GetSockOptInt require syscall.Handle instead of int.
//go:build windows

package sockctrl

import (
	"net"
	"syscall"

	"github.com/scionproto/scion/pkg/private/serrors"
)

func SockControl(c *net.UDPConn, f func(syscall.Handle) error) error {
	rawConn, err := c.SyscallConn()
	if err != nil {
		return serrors.Wrap("sockctrl: error accessing raw connection", err)
	}
	var ctrlErr error
	err = rawConn.Control(func(fd uintptr) {
		ctrlErr = f(syscall.Handle(fd))
	})
	if err != nil {
		return serrors.Wrap("sockctrl: RawConn.Control error", err)
	}
	if ctrlErr != nil {
		return serrors.Wrap("sockctrl: control function error", ctrlErr)
	}
	return nil
}
