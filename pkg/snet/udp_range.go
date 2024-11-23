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

//go:build !windows

package snet

import (
	"errors"
	"net"
	"syscall"

	"github.com/scionproto/scion/pkg/private/serrors"
)

func listenUDPRange(addr *net.UDPAddr, start, end uint16) (*net.UDPConn, error) {
	// XXX(JordiSubira): For now, we iterate on the complete SCION/UDP
	// range, in decreasing order, taking the first unused port.
	//
	// If the defined range, intersects with the well-known port range, i.e.,
	// 1-1023, we just start considering from 1024 onwards.
	// The decreasing order first try to use the higher port numbers, normally used
	// by ephemeral connections, letting free the lower port numbers, normally used
	// by longer-lived applications, e.g., server applications.
	//
	// Ideally we would only take a standard ephemeral range, e.g., 32768-65535,
	// Unfortunately, this range was ocuppied by the old dispatcher.
	// The default range for the dispatched ports is 31000-32767.
	// By configuration other port ranges may be defined and restricting to the default
	// range for applications may cause problems.
	//
	// TODO: Replace this implementation with pseudorandom port checking.
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
		if errors.Is(err, syscall.EADDRINUSE) {
			continue
		}
		return nil, err
	}
	return nil, serrors.Wrap("binding to port range", syscall.EADDRINUSE,
		"start", restrictedStart, "end", end)

}
