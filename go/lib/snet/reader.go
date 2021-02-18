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

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
)

type scionConnReader struct {
	base *scionConnBase
	conn PacketConn

	mtx    sync.Mutex
	buffer []byte
}

func newScionConnReader(base *scionConnBase, conn PacketConn) *scionConnReader {
	return &scionConnReader{
		base:   base,
		conn:   conn,
		buffer: make([]byte, common.MaxMTU),
	}
}

// ReadFrom reads data into b, returning the length of copied data and the
// address of the sender.
// If a message is too long to fit in the supplied buffer, excess bytes may be
// discarded.
func (c *scionConnReader) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := c.read(b)
	return n, a, err
}

// Read reads data into b from a connection with a fixed remote address. If the
// remote address for the connection is unknown, Read returns an error.
// If a message is too long to fit in the supplied buffer, excess bytes may be
// discarded.
func (c *scionConnReader) Read(b []byte) (int, error) {
	n, _, err := c.read(b)
	return n, err
}

// read returns the number of bytes read, the address that sent the bytes and
// an error (if one occurred).
func (c *scionConnReader) read(b []byte) (int, *UDPAddr, error) {
	if c.base.scionNet == nil {
		return 0, nil, serrors.New("SCION network not initialized")
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	pkt := Packet{
		Bytes: Bytes(c.buffer),
	}
	var lastHop net.UDPAddr
	err := c.conn.ReadFrom(&pkt, &lastHop)
	if err != nil {
		return 0, nil, err
	}

	udp, ok := pkt.Payload.(UDPPayload)
	if !ok {
		return 0, nil, serrors.New("unexpected payload", "type", common.TypeOf(pkt.Payload))
	}
	n := copy(b, udp.Payload)

	// Extract remote address.
	// Copy the address data to prevent races. See
	// https://github.com/scionproto/scion/issues/1659.
	remote := &UDPAddr{
		IA: pkt.Source.IA,
		Host: CopyUDPAddr(&net.UDPAddr{
			IP:   pkt.Source.Host.IP(),
			Port: int(udp.SrcPort),
		}),
		Path:    pkt.Path.Copy(),
		NextHop: CopyUDPAddr(&lastHop),
	}
	if err = remote.Path.Reverse(); err != nil {
		return 0, nil, serrors.WrapStr("unable to reverse path on received packet", err)
	}
	return n, remote, nil
}

func (c *scionConnReader) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}
