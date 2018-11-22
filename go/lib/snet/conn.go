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

package snet

import (
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/scmp"
)

const (
	// Receive and send buffer sizes
	BufSize = 1<<16 - 1
)

type Error interface {
	error
	SCMP() *scmp.Hdr
}

var _ Error = (*OpError)(nil)

type OpError struct {
	scmp *scmp.Hdr
}

func (e *OpError) SCMP() *scmp.Hdr {
	return e.scmp
}

func (e *OpError) Error() string {
	return e.scmp.String()
}

var _ net.Conn = (*SCIONConn)(nil)
var _ net.PacketConn = (*SCIONConn)(nil)
var _ Conn = (*SCIONConn)(nil)

type SCIONConn struct {
	conn net.PacketConn
	*scionConnBase
	*scionConnWriter
	*scionConnReader
}

func newSCIONConn(base *scionConnBase, pr pathmgr.Resolver, conn net.PacketConn) *SCIONConn {
	return &SCIONConn{
		conn:            conn,
		scionConnBase:   base,
		scionConnWriter: newScionConnWriter(base, pr, conn),
		scionConnReader: newScionConnReader(base, conn),
	}
}

// DialSCION calls DialSCION with infinite timeout on the default networking
// context.
func DialSCION(network string, laddr, raddr *Addr) (Conn, error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError("SCION network not initialized", nil)
	}
	return DefNetwork.DialSCION(network, laddr, raddr, 0)
}

// DialSCIONWithBindSVC calls DialSCIONWithBindSVC with infinite timeout on the
// default networking context.
func DialSCIONWithBindSVC(network string, laddr, raddr, baddr *Addr,
	svc addr.HostSVC) (Conn, error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError("SCION network not initialized", nil)
	}
	return DefNetwork.DialSCIONWithBindSVC(network, laddr, raddr, baddr, svc, 0)
}

// ListenSCION calls ListenSCION with infinite timeout on the default
// networking context.
func ListenSCION(network string, laddr *Addr) (Conn, error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError("SCION network not initialized", nil)
	}
	return DefNetwork.ListenSCION(network, laddr, 0)
}

// ListenSCIONWithBindSVC calls ListenSCIONWithBindSVC with infinite timeout on
// the default networking context.
func ListenSCIONWithBindSVC(network string, laddr, baddr *Addr, svc addr.HostSVC) (Conn, error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError("SCION network not initialized", nil)
	}
	return DefNetwork.ListenSCIONWithBindSVC(network, laddr, baddr, svc, 0)
}

func (c *SCIONConn) SetDeadline(t time.Time) error {
	if err := c.scionConnReader.SetReadDeadline(t); err != nil {
		return err
	}
	if err := c.scionConnWriter.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}

func (c *SCIONConn) Close() error {
	return c.conn.Close()
}
