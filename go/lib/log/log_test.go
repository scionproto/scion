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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/inconshreveable/log15"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/log/mock_log"
)

func TestTraceFilterHandler(t *testing.T) {
	Convey("Given a base handler...", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHandler := mock_log.NewMockHandler(ctrl)
		logger := log.Root()
		Convey("by default...", func() {
			logger.SetHandler(mockHandler)
			var msgSeenByMockHandler string
			mockHandler.EXPECT().Log(gomock.Any()).Do(func(record *log15.Record) {
				msgSeenByMockHandler = record.Msg
			})
			Convey("debug messages are printed", func() {
				logger.Debug("foo")
				So(msgSeenByMockHandler, ShouldEqual, "foo")
			})
			Convey("trace messages are printed", func() {
				logger.Trace("foo")
				So(msgSeenByMockHandler, ShouldEqual, log.TraceMsgPrefix+"foo")
			})
		})
		Convey("if wrapped by a trace filter handler...", func() {
			handler := log.FilterTraceHandler(mockHandler)
			logger.SetHandler(handler)
			Convey("debug messages are printed", func() {
				var msgSeenByMockHandler string
				mockHandler.EXPECT().Log(gomock.Any()).Do(func(record *log15.Record) {
					msgSeenByMockHandler = record.Msg
				})
				logger.Debug("foo")
				So(msgSeenByMockHandler, ShouldEqual, "foo")
			})
			Convey("trace messages are not printed", func() {
				logger.Trace("foo")
			})
		})
	})

}
