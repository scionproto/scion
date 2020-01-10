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
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/inconshreveable/log15"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/log/mock_log"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestSetupLogConsole(t *testing.T) {
	tmpDir, cleanF := xtest.MustTempDir("", "test-folder")
	defer cleanF()

	tests := map[string]struct {
		dir       string
		assertErr assert.ErrorAssertionFunc
	}{
		"cannot create, errors": {
			dir:       "/sys/aka/doesnt/exist",
			assertErr: assert.Error,
		},

		"can create, nil": {
			dir:       filepath.Join(tmpDir, "new"),
			assertErr: assert.NoError,
		},
	}

	for td, tc := range tests {
		t.Run(td, func(t *testing.T) {
			err := log.SetupLogFile("test", tc.dir, "debug", 0, 0, 0, 0, false)
			tc.assertErr(t, err)
		})
	}
}

func TestTraceFilterHandler(t *testing.T) {
	t.Log("Given a base handler...")

	t.Run("by default...", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHandler := mock_log.NewMockHandler(ctrl)
		logger := log.Root()
		logger.SetHandler(mockHandler)
		var msgSeenByMockHandler string
		mockHandler.EXPECT().Log(gomock.Any()).Do(func(record *log15.Record) {
			msgSeenByMockHandler = record.Msg
		}).AnyTimes()
		t.Log("debug messages are printed")
		logger.Debug("foo")
		assert.Equal(t, msgSeenByMockHandler, "foo")
		t.Log("trace messages are printed")
		logger.Trace("foo")
		assert.Equal(t, msgSeenByMockHandler, log.TraceMsgPrefix+"foo")
	})

	t.Run("if wrapped by a trace filter handler...", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockHandler := mock_log.NewMockHandler(ctrl)
		logger := log.Root()
		handler := log.FilterTraceHandler(mockHandler)
		logger.SetHandler(handler)
		t.Log("debug messages are printed")
		var msgSeenByMockHandler string
		mockHandler.EXPECT().Log(gomock.Any()).Do(func(record *log15.Record) {
			msgSeenByMockHandler = record.Msg
		}).AnyTimes()
		logger.Debug("foo")
		assert.Equal(t, msgSeenByMockHandler, "foo")
		t.Log("trace messages are not printed")
		logger.Trace("foo")
	})

}
