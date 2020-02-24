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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/p2p"
)

const (
	testCtxTimeout = 200 * time.Millisecond
)

func Setup() (*Dispatcher, *Dispatcher, *customObject, *customObject) {
	a2b, b2a := p2p.NewPacketConns()
	dispA := New(a2b, testAdapter, log.Root())
	dispB := New(b2a, testAdapter, log.Root())
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
			recvReply, err := dispA.Request(ctx, request, nil)
			sc.SoMsg("a request err", err, ShouldBeNil)
			sc.SoMsg("a request reply", recvReply, ShouldResemble, reply)
		}, func(sc *xtest.SC) {
			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()
			recvRequest, _, _, err := dispB.RecvFrom(ctx)
			sc.SoMsg("b recv err", err, ShouldBeNil)
			sc.SoMsg("b recv msg", recvRequest, ShouldResemble, request)
			err = dispB.Notify(ctx, reply, nil)
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
			recvReply, err := dispA.Request(ctx, request, nil)
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
			recvReply, err := dispA.Request(ctx, request, nil)
			sc.SoMsg("a request err", err, ShouldNotBeNil)
			sc.SoMsg("a request err timeout", common.IsTimeoutErr(err), ShouldBeTrue)
			sc.SoMsg("a request reply", recvReply, ShouldBeNil)
		}, func(sc *xtest.SC) {
			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()
			// Create reply with bad ID
			badReply := &customObject{73, "reply"}

			recvRequest, _, _, err := dispB.RecvFrom(ctx)
			sc.SoMsg("b recv err", err, ShouldBeNil)
			sc.SoMsg("b recv msg", recvRequest, ShouldResemble, request)
			err = dispB.Notify(ctx, badReply, nil)
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
			err := dispA.Notify(ctx, notification, nil)
			sc.SoMsg("a notify err", err, ShouldBeNil)
		}, func(sc *xtest.SC) {
			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()
			recvNotification, _, _, err := dispB.RecvFrom(ctx)
			sc.SoMsg("b recv err", err, ShouldBeNil)
			sc.SoMsg("b recv notification", recvNotification, ShouldResemble, notification)
		}))
	})
}

func TestUnreliableNotify(t *testing.T) {
	Convey("Setup", t, func() {
		dispA, _, notification, _ := Setup()
		Convey("Unreliable notify and return immediately", func() {
			ctx, cancelF := context.WithTimeout(context.Background(), testCtxTimeout)
			defer cancelF()
			err := dispA.NotifyUnreliable(ctx, notification, nil)
			SoMsg("a notify err", err, ShouldBeNil)
		})
	})
}

func TestMain(m *testing.M) {
	log.Discard()
	os.Exit(m.Run())
}
