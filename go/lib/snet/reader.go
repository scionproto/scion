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
	"context"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spkt"
)

type scionConnReader struct {
	base *scionConnBase

	conn       net.PacketConn
	readMutex  sync.Mutex
	recvBuffer common.RawBytes
}

func newScionConnReader(base *scionConnBase, conn net.PacketConn) *scionConnReader {
	return &scionConnReader{
		base:       base,
		recvBuffer: make(common.RawBytes, BufSize),
		conn:       conn,
	}
}

// ReadFromSCION reads data into b, returning the length of copied data and the
// address of the sender. If the remote address for the connection is already
// known, ReadFromSCION returns an error.
func (c *scionConnReader) ReadFromSCION(b []byte) (int, *Addr, error) {
	return c.read(b, true)
}

func (c *scionConnReader) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.read(b, true)
}

// Read reads data into b from a connection with a fixed remote address. If the
// remote address for the connection is unknown, Read returns an error.
func (c *scionConnReader) Read(b []byte) (int, error) {
	n, _, err := c.read(b, false)
	return n, err
}

// read returns the number of bytes read, the address that sent the bytes and
// an error (if one occurred).
func (c *scionConnReader) read(b []byte, from bool) (int, *Addr, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	var err error
	var remote *Addr
	if c.base.scionNet == nil {
		return 0, nil, common.NewBasicError("SCION network not initialized", nil)
	}
	n, lastHopNetAddr, err := c.conn.ReadFrom(c.recvBuffer)
	if err != nil {
		return 0, nil, common.NewBasicError("Dispatcher read error", err)
	}
	var lastHop *overlay.OverlayAddr
	if from {
		var ok bool
		lastHop, ok = lastHopNetAddr.(*overlay.OverlayAddr)
		if !ok {
			return 0, nil, common.NewBasicError("Invalid lastHop address Type", nil,
				"Actual", lastHopNetAddr)
		}
	}
	pkt := &spkt.ScnPkt{
		DstIA: addr.IA{},
		SrcIA: addr.IA{},
	}
	err = hpkt.ParseScnPkt(pkt, c.recvBuffer[:n])
	if err != nil {
		return 0, nil, common.NewBasicError("SCION packet parse error", err)
	}
	// Copy data, extract address
	n, err = pkt.Pld.WritePld(b)
	if err != nil {
		return 0, nil, common.NewBasicError("Unable to copy payload", err)
	}
	// On UDP4 network we can get either UDP traffic or SCMP messages
	if c.base.net == "udp4" {
		// Extract remote address
		remote = &Addr{
			IA:   pkt.SrcIA,
			Path: pkt.Path,
		}
		// Extract path
		if remote.Path != nil {
			if err = remote.Path.Reverse(); err != nil {
				return 0, nil,
					common.NewBasicError("Unable to reverse path on received packet", err)
			}
		}
		// Extract last hop
		if lastHop != nil {
			// XXX When do we not get a lastHop?
			// Copy the address to prevent races. See
			// https://github.com/scionproto/scion/issues/1659.
			remote.NextHop = lastHop.Copy()
		}
		var err error
		var l4i addr.L4Info
		switch hdr := pkt.L4.(type) {
		case *l4.UDP:
			l4i = addr.NewL4UDPInfo(hdr.SrcPort)
		case *scmp.Hdr:
			l4i = addr.NewL4SCMPInfo()
			c.handleSCMP(hdr, pkt)
			err = &OpError{scmp: hdr}
		default:
			err = common.NewBasicError("Unexpected SCION L4 protocol", nil,
				"expected", "UDP or SCMP", "actual", pkt.L4.L4Type())
		}
		// Copy the address to prevent races. See
		// https://github.com/scionproto/scion/issues/1659.
		remote.Host = &addr.AppAddr{L3: pkt.SrcHost.Copy(), L4: l4i}
		return n, remote, err
	}
	return 0, nil, common.NewBasicError("Unknown network", nil, "net", c.base.net)
}

func (c *scionConnReader) handleSCMP(hdr *scmp.Hdr, pkt *spkt.ScnPkt) {
	// Only handle revocations for now
	if hdr.Class == scmp.C_Path && hdr.Type == scmp.T_P_RevokedIF {
		c.handleSCMPRev(hdr, pkt)
	} else {
		log.Warn("Received unsupported SCMP message", "class", hdr.Class, "type", hdr.Type)
	}
}

func (c *scionConnReader) handleSCMPRev(hdr *scmp.Hdr, pkt *spkt.ScnPkt) {
	scmpPayload, ok := pkt.Pld.(*scmp.Payload)
	if !ok {
		log.Error("Unable to type assert payload to SCMP payload", "type", common.TypeOf(pkt.Pld))
	}
	info, ok := scmpPayload.Info.(*scmp.InfoRevocation)
	if !ok {
		log.Error("Unable to type assert SCMP Info to SCMP Revocation Info",
			"type", common.TypeOf(scmpPayload.Info))
	}
	log.Info("Received SCMP revocation", "header", hdr.String(), "payload", scmpPayload.String())
	if c.base.scionNet.pathResolver != nil {
		c.base.scionNet.pathResolver.RevokeRaw(context.TODO(), info.RawSRev)
	}
}

func (c *scionConnReader) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}
