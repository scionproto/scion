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
	"flag"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/gavv/monotime"
	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/lib/assert"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay"
	"github.com/netsec-ethz/scion/go/lib/sockctrl"
	"github.com/netsec-ethz/scion/go/lib/topology"
)

const recvBufSize = 1 << 20

var sizeIgnore = flag.Bool("overlay.conn.sizeIgnore", true,
	"Ignore failing to set the receive buffer size on a socket.")

type Conn interface {
	Read(common.RawBytes) (int, *ReadMeta, error)
	Write(common.RawBytes) (int, error)
	WriteTo(common.RawBytes, *topology.AddrInfo) (int, error)
	LocalAddr() *topology.AddrInfo
	RemoteAddr() *topology.AddrInfo
	Close() error
}

func New(listen, remote *topology.AddrInfo, labels prometheus.Labels) (Conn, error) {
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
		var c *net.UDPConn
		var err error
		if listen != nil {
			laddr = &net.UDPAddr{IP: listen.IP, Port: listen.L4Port}
		}
		if remote == nil {
			if c, err = net.ListenUDP("udp4", laddr); err != nil {
				return nil, common.NewCError("Error listening on socket",
					"overlay", ot, "listen", listen, "err", err)
			}
		} else {
			raddr = &net.UDPAddr{IP: remote.IP, Port: remote.L4Port}
			if c, err = net.DialUDP("udp4", laddr, raddr); err != nil {
				return nil, common.NewCError("Error setting up connection",
					"overlay", ot, "listen", listen, "remote", remote, "err", err)
			}
		}
		return newConnUDPIPv4(c, listen, remote, labels)
	}
	return nil, common.NewCError(fmt.Sprintf("Unsupported overlay type '%s'", ot))
}

type connUDPIPv4 struct {
	conn      *net.UDPConn
	Listen    *topology.AddrInfo
	Remote    *topology.AddrInfo
	oob       common.RawBytes
	closed    bool
	readMeta  ReadMeta
	tmpRemote topology.AddrInfo
}

func newConnUDPIPv4(c *net.UDPConn, listen, remote *topology.AddrInfo,
	labels prometheus.Labels) (*connUDPIPv4, error) {
	// Set reporting socket options
	if err := sockctrl.SetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_RXQ_OVFL, 1); err != nil {
		return nil, common.NewCError("Error setting SO_RXQ_OVFL socket option", "listen", listen,
			"remote", remote, "err", err)
	}
	if err := sockctrl.SetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1); err != nil {
		return nil, common.NewCError("Error setting SO_TIMESTAMPNS socket option", "listen", listen,
			"remote", remote, "err", err)
	}
	// Set and confirm receive buffer size
	before, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return nil, common.NewCError("Error getting SO_RCVBUF socket option (before)",
			"listen", listen, "remote", remote, "err", err)
	}
	if err = c.SetReadBuffer(recvBufSize); err != nil {
		return nil, common.NewCError("Error setting recv buffer size", "listen", listen,
			"remote", remote, "err", err)
	}
	after, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return nil, common.NewCError("Error getting SO_RCVBUF socket option (after)",
			"listen", listen, "remote", remote, "err", err)
	}
	if after/2 != recvBufSize {
		msg := "Receive buffer size smaller than requested"
		ctx := []interface{}{"expected", recvBufSize, "actual", after / 2, "before", before / 2}
		if !*sizeIgnore {
			return nil, common.NewCError(msg, ctx...)
		}
		log.Warn(msg, ctx...)
	}
	oob := make(common.RawBytes, syscall.CmsgSpace(SizeOfInt)+syscall.CmsgSpace(SizeOfTimespec))
	return &connUDPIPv4{
		conn:      c,
		Listen:    listen,
		Remote:    remote,
		oob:       oob,
		closed:    false,
		tmpRemote: topology.AddrInfo{Overlay: overlay.UDPIPv4, OverlayPort: overlay.EndhostPort},
	}, nil
}

func (c *connUDPIPv4) Read(b common.RawBytes) (int, *ReadMeta, error) {
	c.readMeta.Src = nil
	c.readMeta.RcvOvfl = 0
	c.readMeta.Recvd = 0
	c.readMeta.Read = 0
	n, oobn, _, src, err := c.conn.ReadMsgUDP(b, c.oob)
	c.readMeta.Read = monotime.Now()
	if oobn > 0 {
		c.handleCmsg(c.oob[:oobn])
	}
	if c.readMeta.Recvd == 0 {
		c.readMeta.Recvd = c.readMeta.Read
	}
	c.readMeta.Src = c.Remote
	if c.Remote == nil {
		c.tmpRemote.IP = src.IP
		c.tmpRemote.L4Port = src.Port
		c.readMeta.Src = &c.tmpRemote
	}
	return n, &c.readMeta, err
}

func (c *connUDPIPv4) handleCmsg(oob common.RawBytes) {
	// Based on https://github.com/golang/go/blob/release-branch.go1.8/src/syscall/sockcmsg_unix.go#L49
	// and modified to remove most allocations.
	now := time.Now()
	sizeofCmsgHdr := syscall.CmsgLen(0)
	for sizeofCmsgHdr <= len(oob) {
		hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
		if hdr.Len < syscall.SizeofCmsghdr {
			log.Error("Cmsg from ReadMsgUDP has corrupted header length", "listen", c.Listen,
				"remote", c.Remote, "min", syscall.SizeofCmsghdr, "actual", hdr.Len)
			return
		}
		if uint64(hdr.Len) > uint64(len(oob)) {
			log.Error("Cmsg from ReadMsgUDP longer than remaining buffer",
				"listen", c.Listen, "remote", c.Remote, "max", len(oob), "actual", hdr.Len)
			return
		}
		switch {
		case hdr.Level == syscall.SOL_SOCKET && hdr.Type == syscall.SO_RXQ_OVFL:
			c.readMeta.RcvOvfl = *(*int)(unsafe.Pointer(&oob[sizeofCmsgHdr]))
		case hdr.Level == syscall.SOL_SOCKET && hdr.Type == syscall.SO_TIMESTAMPNS:
			tv := *(*Timespec)(unsafe.Pointer(&oob[sizeofCmsgHdr]))
			since := now.Sub(time.Unix(int64(tv.tv_sec), int64(tv.tv_nsec)))
			// Guard against leap-seconds.
			if since > 0 {
				c.readMeta.Recvd = c.readMeta.Read - since
			}
		}
		// What we actually want is the padded length of the cmsg, but CmsgLen
		// adds a CmsgHdr length to the result, so we subtract that.
		oob = oob[syscall.CmsgLen(int(hdr.Len))-sizeofCmsgHdr:]
	}
}

func (c *connUDPIPv4) Write(b common.RawBytes) (int, error) {
	return c.conn.Write(b)
}

func (c *connUDPIPv4) WriteTo(b common.RawBytes, dst *topology.AddrInfo) (int, error) {
	if c.Remote != nil {
		return c.conn.Write(b)
	}
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
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

type ReadMeta struct {
	Src     *topology.AddrInfo
	RcvOvfl int
	Recvd   time.Duration
	Read    time.Duration
}
