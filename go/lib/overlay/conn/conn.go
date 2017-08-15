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
	"syscall"
	"time"
	"unsafe"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/lib/assert"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/nethack"
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

func New(listen, remote *topology.AddrInfo, labels prometheus.Labels) (Conn, *common.Error) {
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
				return nil, common.NewError("Error listening on socket",
					"overlay", ot, "listen", listen, "err", err)
			}
		} else {
			raddr = &net.UDPAddr{IP: remote.IP, Port: remote.L4Port}
			if c, err = net.DialUDP("udp4", laddr, raddr); err != nil {
				return nil, common.NewError("Error setting up connection",
					"overlay", ot, "listen", listen, "remote", remote, "err", err)
			}
		}
		return newConnUDPIPv4(c, listen, remote, labels)
	}
	return nil, common.NewError(fmt.Sprintf("Unsupported overlay type '%s'", ot))
}

type connUDPIPv4 struct {
	conn    *net.UDPConn
	Listen  *topology.AddrInfo
	Remote  *topology.AddrInfo
	oob     common.RawBytes
	metrics *metrics
	closed  bool
}

func newConnUDPIPv4(c *net.UDPConn, listen, remote *topology.AddrInfo,
	labels prometheus.Labels) (*connUDPIPv4, *common.Error) {
	fd, err := nethack.SocketOf(c)
	if err != nil {
		return nil, common.NewError("Unable to get fd of net.UDPConn", "listen", listen,
			"remote", remote, "err", err)
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RXQ_OVFL, 1); err != nil {
		return nil, common.NewError("Error setting SO_RXQ_OVFL socket option", "listen", listen,
			"remote", remote, "err", err)
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1); err != nil {
		return nil, common.NewError("Error setting SO_TIMESTAMP socket option", "listen", listen,
			"remote", remote, "err", err)
	}
	oob := make(common.RawBytes, syscall.CmsgSpace(SizeOfInt)+syscall.CmsgSpace(SizeOfTimeVal))
	return &connUDPIPv4{
		conn:    c,
		Listen:  listen,
		Remote:  remote,
		oob:     oob,
		metrics: newMetrics(labels),
		closed:  false,
	}, nil
}

func (c *connUDPIPv4) Read(b common.RawBytes) (int, *topology.AddrInfo, error) {
	n, oobn, _, src, err := c.conn.ReadMsgUDP(b, c.oob)
	if oobn > 0 {
		c.handleCmsg(c.oob[:oobn])
	}
	remote := c.Remote
	if remote == nil {
		remote = &topology.AddrInfo{Overlay: overlay.UDPIPv4, IP: src.IP, L4Port: src.Port,
			OverlayPort: overlay.EndhostPort}
	}
	return n, remote, err
}

func (c *connUDPIPv4) handleCmsg(oob common.RawBytes) {
	// TODO(kormat): instead of updating metrics here, stop conforming to
	// net.Conn and pass metadata directly back to the caller of Read(). E.g.,
	// this allows the caller to use the received timestamp.
	cmsgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		log.Debug("Error decoding cmsg data from ReadMsgUdp", "listen", c.Listen,
			"remote", c.Remote, "err", err)
		return
	}
	for _, cmsg := range cmsgs {
		hdr := cmsg.Header
		switch {
		case hdr.Level == syscall.SOL_SOCKET && hdr.Type == syscall.SO_RXQ_OVFL:
			val := *(*int)(unsafe.Pointer(&cmsg.Data[0]))
			c.metrics.recvOvfl.Set(float64(val))
		case hdr.Level == syscall.SOL_SOCKET && hdr.Type == syscall.SO_TIMESTAMP:
			since := time.Since(ParseTimeVal(cmsg.Data))
			// Guard against leap-seconds.
			if since > 0 {
				c.metrics.recvDelay.Add(since.Seconds())
			}
		}
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
