// Copyright 2019 ETH Zurich
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

package ctxconn

import (
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/mocks/context/mock_context"
	"github.com/scionproto/scion/go/lib/svc/internal/ctxconn/mock_ctxconn"
)

const baseUnit = time.Millisecond

func TestCloseConeOnDone(t *testing.T) {
	Convey("", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		Convey("if no deadline and no ctx canceled, close is not called", func() {
			ctx := mock_context.NewMockContext(ctrl)
			ctx.EXPECT().Deadline().Return(time.Time{}, false)
			ctx.EXPECT().Done().Return(make(<-chan struct{})).MaxTimes(1)
			cancelFunc := CloseConnOnDone(ctx, nil)
			cancelFunc()
			Convey("cancel functions safe to call multiple times", func() {
				cancelFunc()
			})
		})
		Convey("if no deadline and ctx canceled, close is called once", func() {
			ctx := mock_context.NewMockContext(ctrl)
			ctx.EXPECT().Deadline().Return(time.Time{}, false)
			ctx.EXPECT().Done().DoAndReturn(
				func() <-chan struct{} {
					c := make(chan struct{})
					close(c)
					return c
				},
			)
			closer := mock_ctxconn.NewMockDeadlineCloser(ctrl)
			closer.EXPECT().Close()
			CloseConnOnDone(ctx, closer)
			time.Sleep(20 * baseUnit)
		})
		Convey("if deadline expires, close is called once", func() {
			ctx := mock_context.NewMockContext(ctrl)
			// Deadline is only used to arm the deadline on the conn; the Done
			// mock unblocks the background goroutine
			deadline := time.Now().Add(0)
			ctx.EXPECT().Deadline().Return(deadline, true)
			ctx.EXPECT().Done().DoAndReturn(
				func() <-chan struct{} {
					// Simulates deadline expiring
					c := make(chan struct{})
					close(c)
					return c
				},
			)
			closer := mock_ctxconn.NewMockDeadlineCloser(ctrl)
			closer.EXPECT().Close()
			closer.EXPECT().SetDeadline(deadline)
			CloseConnOnDone(ctx, closer)
			time.Sleep(20 * baseUnit)
		})
	})
}
