// Copyright 2018 ETH Zurich
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

package snet

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/topology"
)

type scionConnWriter struct {
	conn                PacketConn
	local               *UDPAddr
	remote              *UDPAddr
	dispatchedPortStart uint16
	dispatchedPortEnd   uint16

	mtx    sync.Mutex
	buffer []byte
}

// WriteTo sends b to raddr.
func (c *scionConnWriter) WriteTo(b []byte, raddr net.Addr) (int, error) {
	var (
		dst     SCIONAddress
		port    int
		path    DataplanePath
		nextHop *net.UDPAddr
	)

	switch a := raddr.(type) {
	case nil:
		return 0, serrors.New("Missing remote address")
	case *UDPAddr:
		hostIP, ok := netip.AddrFromSlice(a.Host.IP)
		if !ok {
			return 0, serrors.New("invalid destination host IP", "ip", a.Host.IP)
		}
		dst = SCIONAddress{IA: a.IA, Host: addr.HostIP(hostIP)}
		port, path = a.Host.Port, a.Path
		nextHop = a.NextHop
		if nextHop == nil && c.local.IA.Equal(a.IA) {
			port := a.Host.Port
			if !c.isWithinRange(port) {
				port = topology.EndhostPort
			}
			nextHop = &net.UDPAddr{
				IP:   a.Host.IP,
				Port: port,
				Zone: a.Host.Zone,
			}

		}
	case *SVCAddr:
		dst, port, path = SCIONAddress{IA: a.IA, Host: addr.HostSVC(a.SVC)}, 0, a.Path
		nextHop = a.NextHop
	default:
		return 0, serrors.New("Unable to write to non-SCION address",
			"addr", fmt.Sprintf("%v(%T)", a, a))
	}

	listenHostIP, ok := netip.AddrFromSlice(c.local.Host.IP)
	if !ok {
		return 0, serrors.New("invalid listen host IP", "ip", c.local.Host.IP)
	}

	pkt := &Packet{
		Bytes: Bytes(c.buffer),
		PacketInfo: PacketInfo{
			Destination: dst,
			Source: SCIONAddress{
				IA:   c.local.IA,
				Host: addr.HostIP(listenHostIP),
			},
			Path: path,
			Payload: UDPPayload{
				SrcPort: uint16(c.local.Host.Port),
				DstPort: uint16(port),
				Payload: b,
			},
		},
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()
	if err := c.conn.WriteTo(pkt, nextHop); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Write sends b through a connection with fixed remote address. If the remote
// address for the connection is unknown, Write returns an error.
func (c *scionConnWriter) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.remote)
}

func (c *scionConnWriter) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *scionConnWriter) isWithinRange(port int) bool {
	return port >= int(c.dispatchedPortStart) && port <= int(c.dispatchedPortEnd)
}
