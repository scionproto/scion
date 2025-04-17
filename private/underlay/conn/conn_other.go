// Copyright 2025 SCION Association
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

//go:build go1.9 && !linux

// Package conn implements underlay sockets.
package conn

import (
	"net"
	"net/netip"
	"syscall"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/underlay/sockctrl"
)

// This implementation initConnUDP does not require any linux-specific feature but as a result
// does not enable the binding of multiple sockets to the same local address. This has a small
// performance impact on the router's udpip underlay.
func (cc *connUDPBase) initConnUDP(
	network string,
	laddr, raddr netip.AddrPort,
	cfg *Config) error {

	var c *net.UDPConn
	var err error
	if !laddr.IsValid() {
		return serrors.New("listen address must be specified")
	}
	if !raddr.IsValid() {
		if c, err = net.ListenUDP(network, net.UDPAddrFromAddrPort(laddr)); err != nil {
			return serrors.Wrap("Error listening on socket", err,
				"network", network, "listen", laddr)

		}
	} else {
		if c, err = net.DialUDP(
			network,
			net.UDPAddrFromAddrPort(laddr),
			net.UDPAddrFromAddrPort(raddr),
		); err != nil {
			return serrors.Wrap("Error setting up connection", err,
				"network", network, "listen", laddr, "remote", raddr)
		}
	}

	// Set and confirm send buffer size
	if cfg.SendBufferSize != 0 {
		before, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		if err != nil {
			return serrors.Wrap("Error getting SO_SNDBUF socket option (before)", err,
				"listen", laddr,
				"remote", raddr,
			)
		}
		target := cfg.SendBufferSize
		if err = c.SetWriteBuffer(target); err != nil {
			return serrors.Wrap("Error setting send buffer size", err,
				"listen", laddr,
				"remote", raddr,
			)
		}
		after, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		if err != nil {
			return serrors.Wrap("Error getting SO_SNDBUF socket option (after)", err,
				"listen", laddr,
				"remote", raddr,
			)
		}
		if after/2 < target {
			// Note: kernel doubles value passed in SetSendBuffer, value
			// returned is the doubled value
			log.Info("Send buffer size smaller than requested",
				"expected", target,
				"actual", after/2,
				"before", before/2,
			)
		}
	}

	// Set and confirm receive buffer size
	if cfg.ReceiveBufferSize != 0 {
		before, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		if err != nil {
			return serrors.Wrap("Error getting SO_RCVBUF socket option (before)", err,
				"listen", laddr,
				"remote", raddr,
			)
		}
		target := cfg.ReceiveBufferSize
		if err = c.SetReadBuffer(target); err != nil {
			return serrors.Wrap("Error setting recv buffer size", err,
				"listen", laddr,
				"remote", raddr,
			)
		}
		after, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		if err != nil {
			return serrors.Wrap("Error getting SO_RCVBUF socket option (after)", err,
				"listen", laddr,
				"remote", raddr,
			)
		}
		if after/2 < target {
			// Note: kernel doubles value passed in SetReadBuffer, value
			// returned is the doubled value
			log.Info("Receive buffer size smaller than requested",
				"expected", target,
				"actual", after/2,
				"before", before/2,
			)
		}
	}

	cc.conn = c
	cc.Listen = laddr
	cc.Remote = raddr
	return nil
}

func UDPCanReuseLocal() bool {
	return false
}
