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
	"fmt"
	"testing"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messaging"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/p2p"

	. "github.com/smartystreets/goconvey/convey"
)

func Setup() (*Dispatcher, *Dispatcher, *customObject, *customObject) {
	a2b, b2a := p2p.New()
	dispA := New(messaging.NewRUDP(a2b, log.Root()), testAdapter, log.Root())
	dispB := New(messaging.NewRUDP(b2a, log.Root()), testAdapter, log.Root())
	request := &customObject{8, "request"}
	reply := &customObject{8, "reply"}
	return dispA, dispB, request, reply
}

func TestRequest(t *testing.T) {
	Convey("Setup", t, func() {
		dispA, dispB, request, reply := Setup()
		Convey("Request and reply (Parallel)", xtest.Parallel(func(sc *xtest.SC) {
			ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelF()
			recvReply, err := dispA.Request(ctx, request, &p2p.Addr{})
			sc.SoMsg("a request err", err, ShouldBeNil)
			sc.SoMsg("a request reply", recvReply, ShouldResemble, reply)
		}, func(sc *xtest.SC) {
			ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelF()
			recvRequest, _, err := dispB.RecvFrom(ctx)
			sc.SoMsg("b recv err", err, ShouldBeNil)
			sc.SoMsg("b recv msg", recvRequest, ShouldResemble, request)
			err = dispB.Notify(ctx, reply, &p2p.Addr{})
			sc.SoMsg("b notify err", err, ShouldBeNil)
		}))

		Convey("Request without receiver", func() {
			ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelF()
			recvReply, err := dispA.Request(ctx, request, &p2p.Addr{})
			SoMsg("a request err", err, ShouldNotBeNil)
			SoMsg("a request err timeout", infra.IsTimeout(err), ShouldBeTrue)
			SoMsg("a request reply", recvReply, ShouldBeNil)
			fmt.Println(err)
		})

		Convey("Request, and receive bad reply (Parallel)", xtest.Parallel(func(sc *xtest.SC) {
			ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelF()
			recvReply, err := dispA.Request(ctx, request, &p2p.Addr{})
			sc.SoMsg("a request err", err, ShouldNotBeNil)
			sc.SoMsg("a request err timeout", infra.IsTimeout(err), ShouldBeTrue)
			sc.SoMsg("a request reply", recvReply, ShouldBeNil)
		}, func(sc *xtest.SC) {
			ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
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

func TestNotify(t *testing.T) {
	Convey("Setup", t, func() {
		dispA, dispB, notification, _ := Setup()
		Convey("Notify and receive (Parallel)", xtest.Parallel(func(sc *xtest.SC) {
			ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelF()
			err := dispA.Notify(ctx, notification, &p2p.Addr{})
			sc.SoMsg("a notify err", err, ShouldBeNil)
		}, func(sc *xtest.SC) {
			ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelF()
			recvNotification, _, err := dispB.RecvFrom(ctx)
			sc.SoMsg("b recv err", err, ShouldBeNil)
			sc.SoMsg("b recv notification", recvNotification, ShouldResemble, notification)
		}))

		Convey("Notify, but no ACK", func() {
			// Close dispB to make sure its transport layer doesn't ACK
			ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelF()
			dispB.Close(ctx)
			ctx2, cancelF2 := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelF2()
			err := dispA.Notify(ctx2, notification, &p2p.Addr{})
			SoMsg("a notify err", err, ShouldNotBeNil)
			SoMsg("a notify err timeout", infra.IsTimeout(err), ShouldBeTrue)
		})
	})
}

func TestUnreliableNotify(t *testing.T) {
	Convey("Setup", t, func() {
		dispA, dispB, notification, _ := Setup()
		Convey("Unreliable notify and return immediately", func() {
			// Close dispB to make sure its transport layer doesn't ACK
			ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelF()
			dispB.Close(ctx)
			ctx2, cancelF2 := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelF2()
			err := dispA.NotifyUnreliable(ctx2, notification, &p2p.Addr{})
			SoMsg("a notify err", err, ShouldBeNil)
		})
	})
}
