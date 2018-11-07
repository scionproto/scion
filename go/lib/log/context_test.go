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

package log_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/log/mock_log"
)

func TestLoggerCtxEmbedding(t *testing.T) {
	Convey("Given a context with no logger attached", t, func() {
		ctx, cancelF := context.WithCancel(context.Background())
		defer cancelF()
		Convey("Extracting the logger yields a non-nil logger", func() {
			logger := log.GetLogger(ctx)
			So(logger, ShouldNotBeNil)
		})
	})
	Convey("Given a context with a logger attached", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockLogger := mock_log.NewMockLogger(ctrl)
		ctx := log.AttachLogger(context.Background(), mockLogger)
		Convey("Writing to the logger from the context writes on the correct log", func() {
			logger := log.GetLogger(ctx)
			So(logger, ShouldNotBeNil)
			mockLogger.EXPECT().Debug("Foo")
			logger.Debug("Foo")
		})
	})
}
