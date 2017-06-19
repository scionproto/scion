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

package conn

import (
	"fmt"
	"net"

	"github.com/netsec-ethz/scion/go/lib/assert"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay"
	"github.com/netsec-ethz/scion/go/lib/topology"
)

type Conn interface {
	Read(common.RawBytes) (int, *topology.AddrInfo, error)
	Write(common.RawBytes) (int, error)
	WriteTo(common.RawBytes, *topology.AddrInfo) (int, error)
	LocalAddr() *topology.AddrInfo
	RemoteAddr() *topology.AddrInfo
	Close() error
}

func New(listen, remote *topology.AddrInfo) (Conn, *common.Error) {
	if assert.On {
		assert.Must(listen != nil || remote != nil, "Either listen or remote must be set")
	}
	var ot overlay.Type
	if remote != nil {
		ot = remote.Overlay
	} else {
		ot = listen.Overlay
	}
	switch ot {
	case overlay.UDPIPv4:
		var laddr, raddr *net.UDPAddr
		connection := connUDPIPv4{Listen: listen, Remote: remote}
		if listen != nil {
			laddr = &net.UDPAddr{IP: listen.IP, Port: listen.L4Port}
		}
		if remote == nil {
			c, err := net.ListenUDP("udp4", laddr)
			if err != nil {
				return nil, common.NewError("Error listening on socket",
					"overlay", ot, "listen", listen, "err", err)
			}
			connection.conn = c
		} else {
			raddr = &net.UDPAddr{IP: remote.IP, Port: remote.L4Port}
			c, err := net.DialUDP("udp4", laddr, raddr)
			if err != nil {
				return nil, common.NewError("Error setting up connection",
					"overlay", ot, "listen", listen, "remote", remote, "err", err)
			}
			connection.conn = c
		}
		return &connection, nil
	}
	return nil, common.NewError(fmt.Sprintf("Unsupported overlay type '%s'", ot))
}

type connUDPIPv4 struct {
	conn   *net.UDPConn
	Listen *topology.AddrInfo
	Remote *topology.AddrInfo
}

func (c *connUDPIPv4) Read(b common.RawBytes) (int, *topology.AddrInfo, error) {
	if c.Remote != nil {
		l, err := c.conn.Read(b)
		return l, c.Remote, err
	}
	len, src, err := c.conn.ReadFromUDP(b)
	if err != nil {
		return len, nil, err
	}
	ai := &topology.AddrInfo{Overlay: overlay.UDPIPv4, IP: src.IP, L4Port: src.Port,
		OverlayPort: overlay.EndhostPort}
	return len, ai, nil

}

func (c *connUDPIPv4) Write(b common.RawBytes) (int, error) {
	return c.conn.Write(b)
}

func (c *connUDPIPv4) WriteTo(b common.RawBytes, dst *topology.AddrInfo) (int, error) {
	if assert.On {
		assert.Must(dst.OverlayPort != 0, "OverlayPort must not be 0")
	}
	addr := &net.UDPAddr{IP: dst.IP, Port: dst.OverlayPort}
	return c.conn.WriteTo(b, addr)
}

func (c *connUDPIPv4) LocalAddr() *topology.AddrInfo {
	return c.Listen
}

func (c *connUDPIPv4) RemoteAddr() *topology.AddrInfo {
	return c.Remote
}

func (c *connUDPIPv4) Close() error {
	return c.Close()
}
