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
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/svc/internal/ctxconn/mock_ctxconn"
)

const baseUnit = time.Millisecond

func TestCloseConeOnDone(t *testing.T) {
	Convey("", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		Convey("if no deadline and no ctx canceled, close it not called", func() {
			cancelFunc := CloseConnOnDone(context.Background(), nil)
			cancelFunc()
		})
		Convey("if no deadline and ctx canceled, close is called once", func() {
			ctx, ctxCancelF := context.WithCancel(context.Background())
			ctxCancelF()
			closer := mock_ctxconn.NewMockDeadlineCloser(ctrl)
			closer.EXPECT().Close()
			cancelFunc := CloseConnOnDone(ctx, closer)
			time.Sleep(20 * baseUnit)
			Convey("Cancelling afterwards does not do additional close calls", func() {
				cancelFunc()
			})
		})
		Convey("if deadline expires, close is called once", func() {
			deadline := time.Now().Add(0)

			ctx, cancelF := context.WithDeadline(context.Background(), deadline)
			defer cancelF()

			closer := mock_ctxconn.NewMockDeadlineCloser(ctrl)
			closer.EXPECT().Close()
			closer.EXPECT().SetDeadline(deadline)
			CloseConnOnDone(ctx, closer)
			time.Sleep(20 * baseUnit)
		})
	})
}
