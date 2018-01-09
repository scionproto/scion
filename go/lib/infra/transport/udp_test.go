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

package transport

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/xtest/loopback"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSendUnreliableMsgTo(t *testing.T) {
	Convey("Create RUDP, send unreliable message, and receive same message", t, func() {
		conn := loopback.New()
		udp := NewRUDP(conn, log.Root())

		ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelF()
		err := udp.SendUnreliableMsgTo(ctx, common.RawBytes("1234"), &loopback.Addr{})
		SoMsg("send err", err, ShouldBeNil)

		b, _, err := udp.RecvFrom(ctx)
		SoMsg("recv err", err, ShouldBeNil)
		SoMsg("payload", b, ShouldResemble, common.RawBytes("1234"))
	})
}

func TestSendMsgTo(t *testing.T) {
	Convey("Create RUDP, send reliable message, and receive same message", t, func() {
		conn := loopback.New()
		udp := NewRUDP(conn, log.Root())

		ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelF()
		err := udp.SendMsgTo(ctx, common.RawBytes("1234"), &loopback.Addr{})
		SoMsg("send err", err, ShouldBeNil)

		b, _, err := udp.RecvFrom(ctx)
		SoMsg("recv err", err, ShouldBeNil)
		SoMsg("payload", b, ShouldResemble, common.RawBytes("1234"))

		err = udp.Close(ctx)
		SoMsg("err", err, ShouldBeNil)
	})
}

func TestClose(t *testing.T) {
	Convey("Create RUDP, and close it", t, func() {
		conn := loopback.New()
		udp := NewRUDP(conn, log.Root())
		ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelF()
		err := udp.Close(ctx)
		SoMsg("err", err, ShouldBeNil)
	})
}

func TestSendMsgToBadLink(t *testing.T) {
	Convey("Create RUDP on bad link, send reliable message, should get error", t, func() {
		conn := NewBadLoopback()
		udp := NewRUDP(conn, log.Root())

		ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelF()
		err := udp.SendMsgTo(ctx, common.RawBytes("1234"), &loopback.Addr{})
		SoMsg("send err", err, ShouldNotBeNil)
		SoMsg("send err is timeout", common.IsTimeoutErr(err), ShouldBeTrue)

		ctx2, cancelF2 := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelF2()
		err = udp.Close(ctx2)
		SoMsg("err", err, ShouldBeNil)
	})
}

// Loopback with 100% drop rate
type BadLoopback struct {
	*loopback.Conn
	closed chan struct{}
}

func NewBadLoopback() *BadLoopback {
	return &BadLoopback{
		Conn:   loopback.New(),
		closed: make(chan struct{}),
	}
}

func (c *BadLoopback) ReadFrom(b []byte) (int, net.Addr, error) {
	// Drain conn
	_, _, err := c.Conn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}
	// Block until closed
	select {
	case <-c.closed:
		return 0, nil, io.EOF
	}
}

func (c *BadLoopback) Close() error {
	err := c.Conn.Close()
	if err != nil {
		return err
	}
	close(c.closed)
	return nil
}

func TestMain(m *testing.M) {
	l := log.Root()
	l.SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}
