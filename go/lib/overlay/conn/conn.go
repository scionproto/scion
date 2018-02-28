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

// +build go1.9,linux

package conn

import (
	"flag"
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/sockctrl"
	"github.com/scionproto/scion/go/lib/topology"
)

const recvBufSize = 1 << 20

var oobSize = syscall.CmsgSpace(SizeOfInt) + syscall.CmsgSpace(SizeOfTimespec)
var sizeIgnore = flag.Bool("overlay.conn.sizeIgnore", true,
	"Ignore failing to set the receive buffer size on a socket.")

type Conn interface {
	Read(common.RawBytes) (int, *ReadMeta, error)
	ReadBatch([]ipv4.Message, []ReadMeta) (int, error)
	Write(common.RawBytes) (int, error)
	WriteTo(common.RawBytes, *topology.AddrInfo) (int, error)
	WriteBatch([]ipv4.Message) (int, error)
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
	case overlay.UDPIPv6:
		return newConnUDPIPv6(listen, remote, labels)
	case overlay.UDPIPv4:
		return newConnUDPIPv4(listen, remote, labels)
	}
	return nil, common.NewBasicError("Unsupported overlay type", nil, "overlay", ot)
}

type connUDPIPv4 struct {
	connUDPBase
	pconn *ipv4.PacketConn
}

func newConnUDPIPv4(listen, remote *topology.AddrInfo,
	labels prometheus.Labels) (*connUDPIPv4, error) {

	cc := &connUDPIPv4{}
	if err := cc.initConnUDP("udp4", listen, remote); err != nil {
		return nil, err
	}
	cc.pconn = ipv4.NewPacketConn(cc.conn)
	cc.tmpRemote = topology.AddrInfo{Overlay: overlay.UDPIPv4, OverlayPort: overlay.EndhostPort}
	return cc, nil
}

// ReadBatch reads up to len(msgs) packets, and stores them in msgs, with their
// corresponding ReadMeta in metas. It returns the number of packets read, and an error if any.
func (c *connUDPIPv4) ReadBatch(msgs []ipv4.Message, metas []ReadMeta) (int, error) {
	if assert.On {
		assert.Must(len(msgs) == len(metas), "msgs and metas must be the same length")
	}
	for i := range metas {
		metas[i].Reset()
	}
	n, err := c.pconn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
	readTime := time.Now()
	for i := 0; i < n; i++ {
		msg := msgs[i]
		meta := &metas[i]
		meta.read = readTime
		if msg.NN > 0 {
			c.handleCmsg(msg.OOB[:msg.NN], meta)
		}
		meta.SetSrc(c.Remote, msg.Addr.(*net.UDPAddr), overlay.UDPIPv4)
	}
	return n, err
}

func (c *connUDPIPv4) WriteBatch(msgs []ipv4.Message) (int, error) {
	return c.pconn.WriteBatch(msgs, 0)
}

type connUDPIPv6 struct {
	connUDPBase
	pconn *ipv6.PacketConn
}

func newConnUDPIPv6(listen, remote *topology.AddrInfo,
	labels prometheus.Labels) (*connUDPIPv6, error) {

	cc := &connUDPIPv6{}
	if err := cc.initConnUDP("udp6", listen, remote); err != nil {
		return nil, err
	}
	cc.pconn = ipv6.NewPacketConn(cc.conn)
	cc.tmpRemote = topology.AddrInfo{Overlay: overlay.UDPIPv6, OverlayPort: overlay.EndhostPort}
	return cc, nil
}

// ReadBatch reads up to len(msgs) packets, and stores them in msgs, with their
// corresponding ReadMeta in metas. It returns the number of packets read, and an error if any.
func (c *connUDPIPv6) ReadBatch(msgs []ipv4.Message, metas []ReadMeta) (int, error) {
	if assert.On {
		assert.Must(len(msgs) == len(metas), "msgs and metas must be the same length")
	}
	for i := range metas {
		metas[i].Reset()
	}
	n, err := c.pconn.ReadBatch(msgs, syscall.MSG_WAITFORONE)
	readTime := time.Now()
	for i := 0; i < n; i++ {
		msg := msgs[i]
		meta := &metas[i]
		meta.read = readTime
		if msg.NN > 0 {
			c.handleCmsg(msg.OOB[:msg.NN], meta)
		}
		meta.SetSrc(c.Remote, msg.Addr.(*net.UDPAddr), overlay.UDPIPv6)
	}
	return n, err
}

func (c *connUDPIPv6) WriteBatch(msgs []ipv4.Message) (int, error) {
	return c.pconn.WriteBatch(msgs, 0)
}

type connUDPBase struct {
	conn      *net.UDPConn
	Listen    *topology.AddrInfo
	Remote    *topology.AddrInfo
	oob       common.RawBytes
	closed    bool
	readMeta  ReadMeta
	tmpRemote topology.AddrInfo
}

func (cc *connUDPBase) initConnUDP(network string, listen, remote *topology.AddrInfo) error {
	var laddr, raddr *net.UDPAddr
	var c *net.UDPConn
	var err error
	if listen != nil {
		laddr = &net.UDPAddr{IP: listen.IP, Port: listen.L4Port}
	}
	if remote == nil {
		if c, err = net.ListenUDP(network, laddr); err != nil {
			return common.NewBasicError("Error listening on socket", err,
				"network", network, "listen", listen)
		}
	} else {
		raddr = &net.UDPAddr{IP: remote.IP, Port: remote.L4Port}
		if c, err = net.DialUDP(network, laddr, raddr); err != nil {
			return common.NewBasicError("Error setting up connection", err,
				"network", network, "listen", listen, "remote", remote)
		}
	}
	// Set reporting socket options
	if err := sockctrl.SetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_RXQ_OVFL, 1); err != nil {
		return common.NewBasicError("Error setting SO_RXQ_OVFL socket option", err,
			"listen", listen, "remote", remote)
	}
	if err := sockctrl.SetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1); err != nil {
		return common.NewBasicError("Error setting SO_TIMESTAMPNS socket option", err,
			"listen", listen, "remote", remote)
	}
	// Set and confirm receive buffer size
	before, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return common.NewBasicError("Error getting SO_RCVBUF socket option (before)", err,
			"listen", listen, "remote", remote)
	}
	if err = c.SetReadBuffer(recvBufSize); err != nil {
		return common.NewBasicError("Error setting recv buffer size", err,
			"listen", listen, "remote", remote)
	}
	after, err := sockctrl.GetsockoptInt(c, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return common.NewBasicError("Error getting SO_RCVBUF socket option (after)", err,
			"listen", listen, "remote", remote)
	}
	if after/2 != recvBufSize {
		msg := "Receive buffer size smaller than requested"
		ctx := []interface{}{"expected", recvBufSize, "actual", after / 2, "before", before / 2}
		if !*sizeIgnore {
			return common.NewBasicError(msg, nil, ctx...)
		}
		log.Warn(msg, ctx...)
	}
	oob := make(common.RawBytes, syscall.CmsgSpace(SizeOfInt)+syscall.CmsgSpace(SizeOfTimespec))
	cc.conn = c
	cc.Listen = listen
	cc.Remote = remote
	cc.oob = oob
	return nil
}

func (c *connUDPBase) Read(b common.RawBytes) (int, *ReadMeta, error) {
	c.readMeta.Reset()
	n, oobn, _, src, err := c.conn.ReadMsgUDP(b, c.oob)
	c.readMeta.read = time.Now()
	if oobn > 0 {
		c.handleCmsg(c.oob[:oobn], &c.readMeta)
	}
	if c.Remote != nil {
		c.readMeta.Src.IP = c.Remote.IP
		c.readMeta.Src.L4Port = c.Remote.L4Port
	} else {
		c.readMeta.Src.IP = src.IP
		c.readMeta.Src.L4Port = src.Port
	}
	return n, &c.readMeta, err
}

func (c *connUDPBase) handleCmsg(oob common.RawBytes, meta *ReadMeta) {
	// Based on https://github.com/golang/go/blob/release-branch.go1.8/src/syscall/sockcmsg_unix.go#L49
	// and modified to remove most allocations.
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
			meta.RcvOvfl = *(*int)(unsafe.Pointer(&oob[sizeofCmsgHdr]))
		case hdr.Level == syscall.SOL_SOCKET && hdr.Type == syscall.SO_TIMESTAMPNS:
			tv := *(*Timespec)(unsafe.Pointer(&oob[sizeofCmsgHdr]))
			meta.Recvd = time.Unix(int64(tv.tv_sec), int64(tv.tv_nsec))
			meta.ReadDelay = meta.read.Sub(meta.Recvd)
			// Guard against leap-seconds.
			if meta.ReadDelay < 0 {
				meta.ReadDelay = 0
			}
		}
		// What we actually want is the padded length of the cmsg, but CmsgLen
		// adds a CmsgHdr length to the result, so we subtract that.
		oob = oob[syscall.CmsgLen(int(hdr.Len))-sizeofCmsgHdr:]
	}
}

func (c *connUDPBase) Write(b common.RawBytes) (int, error) {
	return c.conn.Write(b)
}

func (c *connUDPBase) WriteTo(b common.RawBytes, dst *topology.AddrInfo) (int, error) {
	if c.Remote != nil {
		return c.conn.Write(b)
	}
	if assert.On {
		assert.Must(dst.OverlayPort != 0, "OverlayPort must not be 0")
	}
	addr := &net.UDPAddr{IP: dst.IP, Port: dst.OverlayPort}
	return c.conn.WriteTo(b, addr)
}

func (c *connUDPBase) LocalAddr() *topology.AddrInfo {
	return c.Listen
}

func (c *connUDPBase) RemoteAddr() *topology.AddrInfo {
	return c.Remote
}

func (c *connUDPBase) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

type ReadMeta struct {
	Src       topology.AddrInfo
	RcvOvfl   int
	Recvd     time.Time
	read      time.Time
	ReadDelay time.Duration
}

func (m *ReadMeta) Reset() {
	m.Src.Reset()
	m.RcvOvfl = 0
	m.Recvd = time.Unix(0, 0)
	m.read = time.Unix(0, 0)
	m.ReadDelay = 0
}

func (m *ReadMeta) SetSrc(rai *topology.AddrInfo, raddr *net.UDPAddr, ot overlay.Type) {
	if rai != nil {
		m.Src = *rai
		return
	}
	m.Src.Overlay = ot
	m.Src.IP = raddr.IP
	m.Src.L4Port = raddr.Port
	m.Src.OverlayPort = overlay.EndhostPort
}

func NewReadMessages(n int) []ipv4.Message {
	m := make([]ipv4.Message, n)
	for i := range m {
		// Allocate a single-element, to avoid allocations when setting the buffer.
		m[i].Buffers = make([][]byte, 1)
		m[i].OOB = make(common.RawBytes, oobSize)
	}
	return m
}

func NewWriteMessages(n int) []ipv4.Message {
	m := make([]ipv4.Message, n)
	for i := range m {
		// Allocate a single-element, to avoid allocations when setting the buffer.
		m[i].Buffers = make([][]byte, 1)
		m[i].Addr = &net.UDPAddr{}
	}
	return m
}
