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

package disp

import (
	"context"
	"os"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/p2p"
)

const (
	testCtxTimeout = 50 * time.Millisecond
)

func Setup() (*Dispatcher, *Dispatcher, *customObject, *customObject) {
	a2b, b2a := p2p.New()
	dispA := New(transport.NewPacketTransport(a2b), testAdapter, log.Root())
	dispB := New(transport.NewPacketTransport(b2a), testAdapter, log.Root())
	request := &customObject{8, "request"}
	reply := &customObject{8, "reply"}
	return dispA, dispB, request, reply
}

func TestRequestReply(t *testing.T) {
	Convey("Setup", t, func() {
		dispA, dispB, request, reply := Setup()
		Convey("Request and reply (Parallel)", xtest.Parallel(func(sc *xtest.SC) {
			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()
			recvReply, err := dispA.Request(ctx, request, &p2p.Addr{})
			sc.SoMsg("a request err", err, ShouldBeNil)
			sc.SoMsg("a request reply", recvReply, ShouldResemble, reply)
		}, func(sc *xtest.SC) {
			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()
			recvRequest, _, err := dispB.RecvFrom(ctx)
			sc.SoMsg("b recv err", err, ShouldBeNil)
			sc.SoMsg("b recv msg", recvRequest, ShouldResemble, request)
			err = dispB.Notify(ctx, reply, &p2p.Addr{})
			sc.SoMsg("b notify err", err, ShouldBeNil)
		}))
	})
}

func TestRequestNoReceiver(t *testing.T) {
	Convey("Setup", t, func() {
		dispA, _, request, _ := Setup()
		Convey("Request without receiver", func() {
			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()
			recvReply, err := dispA.Request(ctx, request, &p2p.Addr{})
			SoMsg("a request err", err, ShouldNotBeNil)
			SoMsg("a request err timeout", common.IsTimeoutErr(err), ShouldBeTrue)
			SoMsg("a request reply", recvReply, ShouldBeNil)
		})
	})
}

func TestRequestBadReply(t *testing.T) {
	Convey("Setup", t, func() {
		dispA, dispB, request, _ := Setup()
		Convey("Request, and receive bad reply (Parallel)", xtest.Parallel(func(sc *xtest.SC) {
			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()
			recvReply, err := dispA.Request(ctx, request, &p2p.Addr{})
			sc.SoMsg("a request err", err, ShouldNotBeNil)
			sc.SoMsg("a request err timeout", common.IsTimeoutErr(err), ShouldBeTrue)
			sc.SoMsg("a request reply", recvReply, ShouldBeNil)
		}, func(sc *xtest.SC) {
			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()
			// Create reply with bad ID
			badReply := &customObject{73, "reply"}

			recvRequest, _, err := dispB.RecvFrom(ctx)
			sc.SoMsg("b recv err", err, ShouldBeNil)
			sc.SoMsg("b recv msg", recvRequest, ShouldResemble, request)
			err = dispB.Notify(ctx, badReply, &p2p.Addr{})
			sc.SoMsg("b notify err", err, ShouldBeNil)
		}))
	})
}

func TestNotifyOk(t *testing.T) {
	Convey("Setup", t, func() {
		dispA, dispB, notification, _ := Setup()
		Convey("Notify and receive (Parallel)", xtest.Parallel(func(sc *xtest.SC) {
			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()
			err := dispA.Notify(ctx, notification, &p2p.Addr{})
			sc.SoMsg("a notify err", err, ShouldBeNil)
		}, func(sc *xtest.SC) {
			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()
			recvNotification, _, err := dispB.RecvFrom(ctx)
			sc.SoMsg("b recv err", err, ShouldBeNil)
			sc.SoMsg("b recv notification", recvNotification, ShouldResemble, notification)
		}))
	})
}

func TestUnreliableNotify(t *testing.T) {
	Convey("Setup", t, func() {
		dispA, dispB, notification, _ := Setup()
		Convey("Unreliable notify and return immediately", func() {
			// Close dispB to make sure its transport layer doesn't ACK
			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()
			dispB.Close(ctx)
			ctx2, cancelF2 := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF2()
			err := dispA.NotifyUnreliable(ctx2, notification, &p2p.Addr{})
			SoMsg("a notify err", err, ShouldBeNil)
		})
	})
}

func TestMain(m *testing.M) {
	l := log.Root()
	l.SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}
