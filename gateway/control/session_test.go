// Copyright 2020 Anapaya Systems
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

package control_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/gateway/control/mock_control"
	"github.com/scionproto/scion/gateway/pathhealth"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/mock_snet"
)

func TestSessionRun(t *testing.T) {
	t.Run("50ms poll interval", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		path := mock_snet.NewMockPath(ctrl)
		pathMonitorRegistration := mock_control.NewMockPathMonitorRegistration(ctrl)
		// Test will run for 200ms, estimate that at least two polls succeed.
		pathMonitorRegistration.EXPECT().Get().Return(pathhealth.Selection{
			Paths: []snet.Path{path}}).MinTimes(2)

		dataplaneSession := mock_control.NewMockDataplaneSession(ctrl)
		dataplaneSession.EXPECT().SetPaths([]snet.Path{path}).MinTimes(2)

		events := make(chan control.SessionEvent)
		sessionMonitorEvents := make(chan control.SessionEvent)

		session := &control.Session{
			Events:                  events,
			SessionMonitorEvents:    sessionMonitorEvents,
			PathMonitorRegistration: pathMonitorRegistration,
			PathMonitorPollInterval: 50 * time.Millisecond,
			DataplaneSession:        dataplaneSession,
		}

		done := make(chan struct{})
		go func() {
			err := session.Run(context.Background())
			assert.NoError(t, err)
			close(done)
		}()

		time.Sleep(200 * time.Millisecond)

		// Close session monitor event channel and check that the session closes down
		close(sessionMonitorEvents)
		xtest.AssertReadReturnsBefore(t, done, time.Second)
	})
}
