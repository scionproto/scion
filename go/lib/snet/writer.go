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
	"github.com/scionproto/scion/go/lib/topology/overlay"
)

// Possible write errors
const (
	ErrNoAddr        common.ErrMsg = "remote address required, but none set"
	ErrDuplicateAddr common.ErrMsg = "remote address specified as argument, " +
		"but address set in conn"
	ErrAddressIsNil         common.ErrMsg = "address is nil"
	ErrNoApplicationAddress common.ErrMsg = "SCION host address is missing"
	ErrExtraPath            common.ErrMsg = "path set, but none required for local AS"
	ErrBadOverlay           common.ErrMsg = "overlay address not set, " +
		"and construction from SCION address failed"
	ErrMustHavePath common.ErrMsg = "overlay address set, but no path set"
	ErrPath         common.ErrMsg = "no path set, and error during path resolution"
)

const (
	DefaultPathQueryTimeout = 5 * time.Second
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

// WriteToSCION sends b to raddr.
func (c *scionConnWriter) WriteToSCION(b []byte, raddr *Addr) (int, error) {
	return c.write(b, raddr)
}

func (c *scionConnWriter) WriteTo(b []byte, a net.Addr) (int, error) {
	switch addr := a.(type) {
	case *Addr:
		return c.WriteToSCION(b, addr)
	case *UDPAddr:
		return c.WriteToSCION(b, addr.ToAddr())
	case *SVCAddr:
		return c.WriteToSCION(b, addr.ToAddr())
	default:
		return 0, common.NewBasicError("Unable to write to non-SCION address", nil,
			"addr", fmt.Sprintf("%v(%T)", a, a))
	}
}

// Write sends b through a connection with fixed remote address. If the remote
// address for the connection is unknown, Write returns an error.
func (c *scionConnWriter) Write(b []byte) (int, error) {
	return c.write(b, nil)
}

func (c *scionConnWriter) write(b []byte, raddr *Addr) (int, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	pkt := &SCIONPacket{
		Bytes: Bytes(c.buffer),
		SCIONPacketInfo: SCIONPacketInfo{
			Destination: SCIONAddress{IA: raddr.IA, Host: raddr.Host.L3},
			Source: SCIONAddress{IA: c.base.scionNet.localIA,
				Host: addr.HostFromIP(c.base.listen.IP)},
			Path: raddr.Path,
			L4Header: &l4.UDP{
				SrcPort:  uint16(c.base.listen.Port),
				DstPort:  raddr.Host.L4,
				TotalLen: uint16(l4.UDPLen + len(b)),
			},
			Payload: common.RawBytes(b),
		},
	}

	if raddr.NextHop == nil && c.base.scionNet.localIA.Equal(raddr.IA) {
		raddr.NextHop = &net.UDPAddr{IP: raddr.Host.L3.IP(), Port: overlay.EndhostPort}
	}

	if err := c.conn.WriteTo(pkt, raddr.NextHop); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *scionConnWriter) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
