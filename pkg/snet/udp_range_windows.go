// Copyright 2017 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

//go:build windows

package snet

import (
	"errors"
	"net"

	"github.com/scionproto/scion/pkg/private/serrors"
	"golang.org/x/sys/windows"
)

func listenUDPRange(addr *net.UDPAddr, start, end uint16) (*net.UDPConn, error) {
	// Windows sockets return different error codes
	restrictedStart := start
	if start < 1024 {
		restrictedStart = 1024
	}
	for port := end; port >= restrictedStart; port-- {
		pconn, err := net.ListenUDP(addr.Network(), &net.UDPAddr{
			IP:   addr.IP,
			Port: int(port),
		})
		if err == nil {
			return pconn, nil
		}
		if errors.Is(err, windows.WSAEADDRINUSE) {
			continue
		}
		return nil, err
	}
	return nil, serrors.Wrap("binding to port range", windows.WSAEADDRINUSE,
		"start", restrictedStart, "end", end)

}
