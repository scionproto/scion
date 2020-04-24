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
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology/underlay"
)

type scionConnWriter struct {
	base *scionConnBase
	conn PacketConn

	mtx    sync.Mutex
	buffer common.RawBytes
}

func newScionConnWriter(base *scionConnBase, querier PathQuerier,
	conn PacketConn) *scionConnWriter {

	return &scionConnWriter{
		base:   base,
		conn:   conn,
		buffer: make(common.RawBytes, common.MaxMTU),
	}
}

// WriteTo sends b to raddr.
func (c *scionConnWriter) WriteTo(b []byte, raddr net.Addr) (int, error) {
	var (
		dst     SCIONAddress
		port    int
		path    *spath.Path
		nextHop *net.UDPAddr
	)

	switch a := raddr.(type) {
	case nil:
		return 0, common.NewBasicError("Missing remote address", nil)
	case *UDPAddr:
		dst, port, path = SCIONAddress{IA: a.IA, Host: addr.HostFromIP(a.Host.IP)},
			a.Host.Port, a.Path
		nextHop = a.NextHop
		if nextHop == nil && c.base.scionNet.localIA.Equal(a.IA) {
			nextHop = &net.UDPAddr{
				IP:   a.Host.IP,
				Port: underlay.EndhostPort,
				Zone: a.Host.Zone,
			}

		}
	case *SVCAddr:
		dst, port, path = SCIONAddress{IA: a.IA, Host: a.SVC}, 0, a.Path
		nextHop = a.NextHop
	default:
		return 0, common.NewBasicError("Unable to write to non-SCION address", nil,
			"addr", fmt.Sprintf("%v(%T)", a, a))
	}

	pkt := &Packet{
		Bytes: Bytes(c.buffer),
		PacketInfo: PacketInfo{
			Destination: dst,
			Source: SCIONAddress{IA: c.base.scionNet.localIA,
				Host: addr.HostFromIP(c.base.listen.IP)},
			Path: path,
			L4Header: &l4.UDP{
				SrcPort:  uint16(c.base.listen.Port),
				DstPort:  uint16(port),
				TotalLen: uint16(l4.UDPLen + len(b)),
			},
			Payload: common.RawBytes(b),
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
	return c.WriteTo(b, c.base.remote)
}

func (c *scionConnWriter) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
