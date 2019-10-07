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

package snet

import (
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/serrors"
)

type scionConnReader struct {
	base *scionConnBase
	conn PacketConn

	mtx    sync.Mutex
	buffer common.RawBytes
}

func newScionConnReader(base *scionConnBase, conn PacketConn) *scionConnReader {
	return &scionConnReader{
		base:   base,
		conn:   conn,
		buffer: make(common.RawBytes, common.MaxMTU),
	}
}

// ReadFromSCION reads data into b, returning the length of copied data and the
// address of the sender. If the remote address for the connection is already
// known, ReadFromSCION returns an error.
func (c *scionConnReader) ReadFromSCION(b []byte) (int, *Addr, error) {
	return c.read(b)
}

func (c *scionConnReader) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.read(b)
}

// Read reads data into b from a connection with a fixed remote address. If the
// remote address for the connection is unknown, Read returns an error.
func (c *scionConnReader) Read(b []byte) (int, error) {
	n, _, err := c.read(b)
	return n, err
}

// read returns the number of bytes read, the address that sent the bytes and
// an error (if one occurred).
func (c *scionConnReader) read(b []byte) (int, *Addr, error) {
	if c.base.scionNet == nil {
		return 0, nil, serrors.New("SCION network not initialized")
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	pkt := SCIONPacket{
		Bytes: Bytes(c.buffer),
	}
	var lastHop overlay.OverlayAddr
	err := c.conn.ReadFrom(&pkt, &lastHop)
	if err != nil {
		return 0, nil, err
	}

	// Copy data, extract address
	n, err := pkt.Payload.WritePld(b)
	if err != nil {
		return 0, nil, common.NewBasicError("Unable to copy payload", err)
	}

	var remote *Addr
	// On UDP4 network we can get either UDP traffic or SCMP messages
	if c.base.net == "udp4" {
		// Extract remote address
		remote = &Addr{
			IA: pkt.Source.IA,
		}

		// Extract path
		if pkt.Path != nil {
			remote.Path = pkt.Path.Copy()
			if err = remote.Path.Reverse(); err != nil {
				return 0, nil,
					common.NewBasicError("Unable to reverse path on received packet", err)
			}
		}

		// Copy the address to prevent races. See
		// https://github.com/scionproto/scion/issues/1659.
		remote.NextHop = lastHop.Copy()

		var err error
		var l4i addr.L4Info
		switch hdr := pkt.L4Header.(type) {
		case *l4.UDP:
			l4i = addr.NewL4UDPInfo(hdr.SrcPort)
		case *scmp.Hdr:
			l4i = addr.NewL4SCMPInfo()
		default:
			err = common.NewBasicError("Unexpected SCION L4 protocol", nil,
				"expected", "UDP or SCMP", "actual", pkt.L4Header.L4Type())
		}
		// Copy the address to prevent races. See
		// https://github.com/scionproto/scion/issues/1659.
		remote.Host = &addr.AppAddr{L3: pkt.Source.Host.Copy(), L4: l4i}
		return n, remote, err
	}
	return 0, nil, common.NewBasicError("Unknown network", nil, "net", c.base.net)
}

func (c *scionConnReader) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}
