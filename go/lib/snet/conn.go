// Copyright 2017 ETH Zurich
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
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/slayers"
)

type OpError struct {
	typeCode slayers.SCMPTypeCode
	revInfo  *path_mgmt.RevInfo
}

func (e *OpError) RevInfo() *path_mgmt.RevInfo {
	return e.revInfo
}

func (e *OpError) Error() string {
	return e.typeCode.String()
}

var _ net.Conn = (*Conn)(nil)
var _ net.PacketConn = (*Conn)(nil)

type Conn struct {
	conn PacketConn
	scionConnBase
	scionConnWriter
	scionConnReader
}

func newConn(base scionConnBase, conn PacketConn, replyPather ReplyPather) *Conn {
	c := &Conn{
		conn:          conn,
		scionConnBase: base,
	}
	c.scionConnWriter = scionConnWriter{
		base:   &c.scionConnBase,
		conn:   conn,
		buffer: make([]byte, common.SupportedMTU),
	}
	c.scionConnReader = scionConnReader{
		base:        &c.scionConnBase,
		conn:        conn,
		buffer:      make([]byte, common.SupportedMTU),
		replyPather: replyPather,
	}
	return c
}

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.scionConnReader.SetReadDeadline(t); err != nil {
		return err
	}
	if err := c.scionConnWriter.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}

func (c *Conn) Close() error {
	return c.conn.Close()
}
