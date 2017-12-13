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
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/xtest"
)

func Test_FunctionWT_Wait(t *testing.T) {
	Convey("Initialize table", t, func() {
		ftw := newWaitTable(testAdapter.MsgKey)
		request, reply := &customObject{8, "request"}, &customObject{8, "reply"}

		Convey("Normal request/reply", func() {
			// channel to force reply after request is added to table
			sequencer := make(chan struct{})
			Convey("Parallel", xtest.Parallel(func(sc *xtest.SC) {
				err := ftw.AddRequest(request)
				sc.SoMsg("err add", err, ShouldBeNil)
				sequencer <- struct{}{}
				ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancelF()
				recvReply, err := ftw.WaitForReply(ctx, request)
				sc.SoMsg("err wait", err, ShouldBeNil)
				sc.SoMsg("reply", recvReply, ShouldResemble, reply)
			}, func(sc *xtest.SC) {
				<-sequencer
				err := ftw.Reply(reply)
				sc.SoMsg("err reply", err, ShouldBeNil)
			}))
		})

		Convey("Double reply", func() {
			// channel to force reply after request is added to table
			sequencer := make(chan struct{})
			Convey("Parallel", xtest.Parallel(func(sc *xtest.SC) {
				err := ftw.AddRequest(request)
				sc.SoMsg("err add", err, ShouldBeNil)
				sequencer <- struct{}{}
				// Ignore reply to force duplicate reply detection
			}, func(sc *xtest.SC) {
				<-sequencer
				err := ftw.Reply(reply)
				sc.SoMsg("err reply #1", err, ShouldBeNil)
				err = ftw.Reply(reply)
				sc.SoMsg("err reply #2", err, ShouldNotBeNil)
			}))
		})

		Convey("Reply without request", func() {
			err := ftw.Reply(reply)
			SoMsg("err reply", err, ShouldNotBeNil)
		})

		Convey("Reply with deleted request", func() {
			err := ftw.AddRequest(request)
			SoMsg("err add", err, ShouldBeNil)
			ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancelF()
			recvReply, err := ftw.WaitForReply(ctx, request)
			SoMsg("err wait", err, ShouldNotBeNil)
			SoMsg("reply", recvReply, ShouldBeNil)
			ftw.CancelRequest(request)
			err = ftw.Reply(reply)
			SoMsg("err reply", err, ShouldNotBeNil)
		})
	})
}
