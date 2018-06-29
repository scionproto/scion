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

package transport

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/util"
)

var _ infra.Transport = (*PacketTransport)(nil)

// PacketTransport implements interface Transport by wrapping around a
// net.PacketConn. The reliability of the underlying net.PacketConn defines the
// semantics behind SendMsgTo and SendUnreliableMsgTo.
//
// For PacketTransports running on top of UDP, both SendMsgTo and
// SendUnreliableMsgTo are unreliable.
//
// For PacketTransports running on top of UNIX domain socket with SOCK_DGRAM or
// Reliable socket, both SendMsgTo and SendUnreliableMsgTo guarantee reliable
// delivery to the other other end of the socket. Note that in this case, the
// reliability only extends to the guarantee that the message was not lost in
// transfer. It is not a guarantee that the server has read and processed the
// message.
type PacketTransport struct {
	conn net.PacketConn
	// While conn is safe for use from multiple goroutines, deadlines are
	// global so it is not safe to enforce two at the same time. Thus, to
	// meet context deadlines we serialize access to the conn.
	writeLock *util.ChannelLock
	readLock  *util.ChannelLock
}

func NewPacketTransport(conn net.PacketConn) *PacketTransport {
	return &PacketTransport{
		conn:      conn,
		writeLock: util.NewChannelLock(),
		readLock:  util.NewChannelLock(),
	}
}

func (u *PacketTransport) SendUnreliableMsgTo(ctx context.Context, b common.RawBytes,
	address net.Addr) error {

	select {
	case <-u.writeLock.Lock():
		defer u.writeLock.Unlock()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := setWriteDeadlineFromCtx(u.conn, ctx); err != nil {
		return err
	}
	n, err := u.conn.WriteTo(b, address)
	if n != len(b) {
		return common.NewBasicError("Wrote incomplete message", err, "wrote", n, "expected", len(b))
	}
	return err
}

func (u *PacketTransport) SendMsgTo(ctx context.Context, b common.RawBytes,
	address net.Addr) error {

	return u.SendUnreliableMsgTo(ctx, b, address)
}

func (u *PacketTransport) RecvFrom(ctx context.Context) (common.RawBytes, net.Addr, error) {
	select {
	case <-u.readLock.Lock():
		defer u.readLock.Unlock()
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	if err := setReadDeadlineFromCtx(u.conn, ctx); err != nil {
		return nil, nil, err
	}
	b := make(common.RawBytes, common.MaxMTU)
	n, address, err := u.conn.ReadFrom(b)
	return b[:n], address, err
}

func (u *PacketTransport) Close(context.Context) error {
	return u.conn.Close()
}

func setWriteDeadlineFromCtx(conn net.PacketConn, ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); ok {
		return conn.SetWriteDeadline(deadline)
	}
	return conn.SetWriteDeadline(time.Time{})
}

func setReadDeadlineFromCtx(conn net.PacketConn, ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); ok {
		return conn.SetReadDeadline(deadline)
	}
	return conn.SetReadDeadline(time.Time{})
}
