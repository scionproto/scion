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
	"net/netip"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// ReplyPather creates reply paths based on the incoming RawPath.
type ReplyPather interface {
	// ReplyPath takes the RawPath of an incoming packet and creates a path
	// that can be used in a reply.
	ReplyPath(RawPath) (DataplanePath, error)
}

type scionConnReader struct {
	replyPather ReplyPather
	conn        PacketConn
	local       *UDPAddr

	mtx    sync.Mutex
	buffer []byte
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
	// TODO(JordiSubira): Add UTs for this
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

	rpath, ok := pkt.Path.(RawPath)
	if !ok {
		return 0, nil, serrors.New("unexpected path", "type", common.TypeOf(pkt.Path))
	}
	replyPath, err := c.replyPather.ReplyPath(rpath)
	if err != nil {
		return 0, nil, serrors.Wrap("creating reply path", err)
	}

	udp, ok := pkt.Payload.(UDPPayload)
	if !ok {
		return 0, nil, serrors.New("unexpected payload", "type", common.TypeOf(pkt.Payload))
	}

	// XXX(JordiSubira): We explicitly forbid nil or unspecified address in the current constructor
	// for Conn.
	// If this were ever to change, we would always fall into the following if statement, then
	// we would like to replace this logic (e.g., using IP_PKTINFO, with its caveats).
	pktAddrPort := netip.AddrPortFrom(pkt.Destination.Host.IP(), udp.DstPort)
	if c.local.IA != pkt.Destination.IA ||
		c.local.Host.AddrPort() != pktAddrPort {
		return 0, nil, serrors.New("packet is destined to a different host",
			"local_isd_as", c.local.IA,
			"local_host", c.local.Host,
			"pkt_destination_isd_as", pkt.Destination.IA,
			"pkt_destination_host", pktAddrPort,
		)
	}

	// Extract remote address.
	// Copy the address data to prevent races. See
	// https://github.com/scionproto/scion/issues/1659.
	remote := &UDPAddr{
		IA: pkt.Source.IA,
		Host: &net.UDPAddr{
			IP:   pkt.Source.Host.IP().AsSlice(),
			Port: int(udp.SrcPort),
		},
		Path:    replyPath,
		NextHop: CopyUDPAddr(&lastHop),
	}
	n := copy(b, udp.Payload)
	return n, remote, nil
}

func (c *scionConnReader) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}
