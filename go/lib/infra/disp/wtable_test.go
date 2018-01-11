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

func TestWT(t *testing.T) {
	Convey("Initialize table", t, func() {
		wt := newWaitTable(testAdapter.MsgKey)
		request, reply := &customObject{8, "request"}, &customObject{8, "reply"}

		Convey("Normal request/reply", func() {
			err := wt.addRequest(request)
			SoMsg("add err", err, ShouldBeNil)
			Convey("Parallel", xtest.Parallel(func(sc *xtest.SC) {
				ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancelF()
				recvReply, err := wt.waitForReply(ctx, request)
				sc.SoMsg("wait err", err, ShouldBeNil)
				sc.SoMsg("reply", recvReply, ShouldResemble, reply)
			}, func(sc *xtest.SC) {
				found, err := wt.reply(reply)
				sc.SoMsg("reply err", err, ShouldBeNil)
				sc.SoMsg("reply found", found, ShouldBeTrue)
			}))
		})

		Convey("Double reply", func() {
			err := wt.addRequest(request)
			SoMsg("err add", err, ShouldBeNil)
			found, err := wt.reply(reply)
			SoMsg("reply #1 err", err, ShouldBeNil)
			SoMsg("reply #1 found", found, ShouldBeTrue)
			_, err = wt.reply(reply)
			SoMsg("reply #2 err", err, ShouldNotBeNil)
		})

		Convey("Reply without request", func() {
			found, err := wt.reply(reply)
			SoMsg("reply err", err, ShouldBeNil)
			SoMsg("reply found", found, ShouldBeFalse)
		})

		Convey("Reply with deleted request", func() {
			err := wt.addRequest(request)
			SoMsg("add err", err, ShouldBeNil)
			ctx, cancelF := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancelF()
			recvReply, err := wt.waitForReply(ctx, request)
			SoMsg("wait err", err, ShouldNotBeNil)
			SoMsg("reply", recvReply, ShouldBeNil)
			wt.cancelRequest(request)
			found, err := wt.reply(reply)
			SoMsg("reply err", err, ShouldBeNil)
			SoMsg("reply found", found, ShouldBeFalse)
		})

		Convey("Method call on destroyed table", func() {
			wt.Destroy()
			err := wt.addRequest(request)
			SoMsg("addRequest err", err, ShouldNotBeNil)
			_, err = wt.waitForReply(context.TODO(), request)
			SoMsg("waitForReply err", err, ShouldNotBeNil)
			_, err = wt.reply(request)
			SoMsg("reply err", err, ShouldNotBeNil)
		})
	})
}
